/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1 "github.com/kube-vm-project/eSwitch/api/v1"
	"github.com/kube-vm-project/eSwitch/pkg/networkswitch"
)

var eSwitchFinalizer = "eswitch.kube-vm.io/finalizer"

// EswitchReconciler reconciles a Eswitch object
type EswitchReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=eswitchconfig.kube-vm.io,resources=eswitches,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=eswitchconfig.kube-vm.io,resources=eswitches/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=eswitchconfig.kube-vm.io,resources=eswitches/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Eswitch object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.0/pkg/reconcile
func (r *EswitchReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	var eswitch v1.Eswitch

	if err := r.Get(ctx, req.NamespacedName, &eswitch); err != nil {
		//log.Error(err, "unable to fetch Switch configuration")
		// we'll ignore not-found errors, since they can't be fixed by an immediate
		// requeue (we'll need to wait for a new notification), and we can get them
		// on deleted requests.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if eswitch.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(&eswitch, eSwitchFinalizer) {
			controllerutil.AddFinalizer(&eswitch, eSwitchFinalizer)
			if err := r.Update(ctx, &eswitch); err != nil {
				return ctrl.Result{}, err
			}
			// return here as it should be reconciled again
			return ctrl.Result{}, nil
		}
	} else {
		log.Info("removing", "switch name", eswitch.Name)

		if !controllerutil.ContainsFinalizer(&eswitch, eSwitchFinalizer) {
			// Clean up resources
		}
		err := networkswitch.DownAll()
		if err != nil {
			log.Error(err, "bringing switch down")
		}

		controllerutil.RemoveFinalizer(&eswitch, eSwitchFinalizer)
		if err := r.Update(ctx, &eswitch); err != nil {
			return ctrl.Result{}, err
		}

		// Stop reconciliation as the item is being deleted
		return ctrl.Result{}, nil
	}

	bg, err := parseSwitchConfig(&eswitch)
	if err != nil {
		log.Error(err, "parsing switch configuration")
		return ctrl.Result{RequeueAfter: time.Second * 5}, err

	}

	err = bg.Up()
	if err != nil {
		log.Error(err, "bringing switch up")
		return ctrl.Result{RequeueAfter: time.Second * 5}, err

	}
	log.Info("switch programmed", "switch name", eswitch.Name)
	eswitch.Status.Configured = true
	err = r.Client.Status().Update(context.TODO(), &eswitch, &client.SubResourceUpdateOptions{})
	if err != nil {
		log.Error(err, "unable to update switch")
	}
	bg.PrettyPrint() // todo - don't need this
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *EswitchReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1.Eswitch{}).
		Named("eswitch").
		Complete(r)
}

func parseSwitchConfig(config *v1.Eswitch) (*networkswitch.BridgeGroup, error) {
	ifaces := make(map[string]networkswitch.PortSettings)
	for x := range config.Spec.Ports {
		iface := networkswitch.PortSettings{
			Trunk:   false, //todo
			PVID:    uint16(config.Spec.Ports[x].PVID),
			Vlans:   config.Spec.Ports[x].VLANS,
			XDPMode: config.Spec.Ports[x].XDPMode,
			// Tap:              tap,
			Transparent:      false,
			IngressFiltering: true,
			HookDrop:         "",
			HookEgress:       "",
		}
		iface.Validate()
		ifaces[config.Spec.Ports[x].Interface] = iface
	}

	ports := &networkswitch.BridgeGroup{
		IfMap:        make(map[string]*networkswitch.SwitchPort),
		IfMapByIndex: make(map[uint16]*networkswitch.SwitchPort),
		IfList:       []*networkswitch.SwitchPort{},
	}
	for ifName, ifSettings := range ifaces {
		ifSettings.Validate()

		err := ports.AddPort(ifName, ifSettings)
		if err != nil {
			return nil, err
		}
	}
	ports.IfList = ports.BuildPortList()

	return ports, nil
}
