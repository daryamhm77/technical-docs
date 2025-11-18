# Acceleration Data Flow

```mermaid
flowchart TD
    %% =====================
    %%   NODES
    %% =====================

    %% INPUT
    start([Acceleration data received])

    %% PROCESSING
    process1[First process of device data stage]
    enrich[Add std, accDuration, missData, accStatus, sensor info]

    %% DECISION
    gpsCheck{GPS data arrived before?}

    %% BRANCHES
    returnSignal([Return signal])
    extract[Extract acceleration data & point times]

    %% DEVICE PATH
    device[Device]
    defaultSensor[/Default sensor/]
    signal[Signal]

    %% STORAGE / QUEUE
    store[(Store in Database)]
    queue[[Send extracted acc data to aiAccelerationQueue]]

    %% END
    END([End])

    %% =====================
    %%   MAIN FLOW
    %% =====================

    start --> process1
    process1 --> enrich
    enrich --> gpsCheck

    gpsCheck -- Yes --> returnSignal
    gpsCheck -- No --> extract

    returnSignal --> END

    extract --> queue
    extract --> store
    queue --> END

    %% DEVICE SIDE FLOW
    process1 --> device
    device --> defaultSensor
    defaultSensor --> extract
    enrich --> signal
