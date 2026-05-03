import React from "react";
import ReactSpeedometer from "react-d3-speedometer";

const Speedometer = () => {
  return (
    <ReactSpeedometer
      maxValue={100}
      value={62}
      needleColor="black"
      startColor="green"
      endColor="red"
      segments={10}
      height={220}
    />
  );
};

export default Speedometer;
