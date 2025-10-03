import { Component } from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';

import NProgress from 'nprogress';

import { MODEL, fetchSubscribers, fetchSubscriber, createSubscriber, updateSubscriber } from 'modules/crud/subscriber';
import { fetchProfiles } from 'modules/crud/profile';
import { clearActionStatus } from 'modules/crud/actions';
import { select, selectActionStatus } from 'modules/crud/selectors';
import * as Notification from 'modules/notification/actions';

import { Subscriber } from 'components';

import traverse from 'traverse';

const formData = {
  "security": {
    k: "465B5CE8 B199B49F AA5F0A2E E238A6BC",
    amf: "8000",
    op_value: "E8ED289D EBA952E4 283B54E8 8E6183CA",
  },
  "ambr": {
    "downlink": {
      "value": 1,
      "unit": 3
    },
    "uplink": {
      "value": 1,
      "unit": 3
    }
  },
  "slice": [{
    "sst": 1,
    "default_indicator": true,
    "session": [{
        "name": "internet",
        "type": 3,
        "ambr": {
          "downlink": {
            "value": 1,
            "unit": 3
          },
          "uplink": {
            "value": 1,
            "unit": 3
          }
        },
        "qos": {
          "index": 9,
          "arp": {
            "priority_level": 8,
            "pre_emption_capability": 1,
            "pre_emption_vulnerability": 1
          }
        },
    }]
  }]
}

class Document extends Component {
  static propTypes = {
    action: PropTypes.string,
    visible: PropTypes.bool, 
    onHide: PropTypes.func
  }

  state = {
    formData
  }

  componentWillMount() {
    const { subscriber, profiles, dispatch } = this.props

    if (subscriber.needsFetch) {
      dispatch(subscriber.fetch)
    }
    if (profiles.needsFetch) {
      dispatch(profiles.fetch)
    }
  }

  componentWillReceiveProps(nextProps) {
    const { subscriber, profiles, status } = nextProps
    const { dispatch, action, onHide } = this.props

    if (subscriber.needsFetch) {
      dispatch(subscriber.fetch)
    }
    if (profiles.needsFetch) {
      dispatch(profiles.fetch)
    }

    if (subscriber.data) {
      // Create a copy of the subscriber data to avoid modifying the original
      const processedData = JSON.parse(JSON.stringify(subscriber.data));

      if (processedData.security) {
        // Always mask encrypted keys - check if keys contain ':' which indicates encryption
        // This handles both update and create scenarios
        if (processedData.security.k && processedData.security.k.includes(':')) {
          processedData.security.k = '********************************';
        }
        if (processedData.security.opc && processedData.security.opc.includes(':')) {
          processedData.security.opc = '********************************';
        }
        if (processedData.security.op && processedData.security.op.includes(':')) {
          processedData.security.op = '********************************';
        }
        
        // Convert OPC/OP to op_value for form display
        if (processedData.security.opc) {
          processedData.security.op_type = 0;
          processedData.security.op_value = processedData.security.opc;
        } else {
          processedData.security.op_type = 1;
          processedData.security.op_value = processedData.security.op;
        }
      }

      this.setState({ formData: processedData })
    } else {
      this.setState({ formData });
    }

    if (status.response) {
      NProgress.configure({ 
        parent: 'body',
        trickleSpeed: 5
      });
      NProgress.done(true);

      const message = action === 'create' ? "New subscriber created" : `${status.id} subscriber updated`;

      dispatch(Notification.success({
        title: 'Subscriber',
        message
      }));

      dispatch(clearActionStatus(MODEL, action));
      onHide();
    } 

    if (status.error) {
      NProgress.configure({ 
        parent: 'body',
        trickleSpeed: 5
      });
      NProgress.done(true);

      const response = ((status || {}).error || {}).response || {};

      let title = 'Unknown Code';
      let message = 'Unknown Error';
      if (response.data && response.data.name && response.data.message) {
        title = response.data.name;
        message = response.data.message;
      } else {
        title = response.status;
        message = response.statusText;
      }

      dispatch(Notification.error({
        title,
        message,
        autoDismiss: 0,
        action: {
          label: 'Dismiss',
          callback: () => onHide()
        }
      }));
      dispatch(clearActionStatus(MODEL, action));
    }
  }

  render() {
    const {
      validate,
      handleSubmit,
      handleError
    } = this;

    const { 
      visible,
      action,
      status,
      subscriber,
      profiles,
      onHide
    } = this.props

    // Ensure masked data is passed to the Edit component
    const maskedFormData = { ...this.state.formData };
    
    // Apply masking to formData before passing to Edit component
    if (maskedFormData.security) {
      // Always mask encrypted keys - check if keys contain ':' which indicates encryption
      if (maskedFormData.security.k && maskedFormData.security.k.includes(':')) {
        maskedFormData.security.k = '********************************';
      }
      if (maskedFormData.security.opc && maskedFormData.security.opc.includes(':')) {
        maskedFormData.security.opc = '********************************';
      }
      if (maskedFormData.security.op && maskedFormData.security.op.includes(':')) {
        maskedFormData.security.op = '********************************';
      }
    }

    return (
      <Subscriber.Edit
        visible={visible} 
        action={action}
        formData={maskedFormData}
        profiles={profiles.data}
        isLoading={subscriber.isLoading && !status.pending}
        validate={validate}
        onHide={onHide}
        onSubmit={handleSubmit}
        onError={handleError} />
    )
  }
}

Document = connect(
  (state, props) => ({ 
    subscribers: select(fetchSubscribers(), state.crud),
    subscriber: select(fetchSubscriber(props.imsi), state.crud),
    profiles: select(fetchProfiles(), state.crud),
    status: selectActionStatus(MODEL, state.crud, props.action)
  })
)(Document);

export default Document;
