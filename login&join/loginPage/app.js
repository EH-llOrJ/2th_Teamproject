import { GlowParticle } from "./glowParticle.js";

const COLORS = [
  // { r: 45, g: 74, b: 227 }, //blue
  // { r: 250, g: 255, b: 89 }, //yellow
  // { r: 255, g: 104, b: 248 }, //pupple
  // { r: 44, g: 209, b: 252 }, //skyblue
  // { r: 54, g: 233, b: 84 }, //green
  // { r: 87, g: 3, b: 170 },
  // { r: 128, g: 0, b: 128 },
  // { r: 2, g: 2, b: 51 },
  // { r: 27, g: 27, b: 27 },
  // { r: 0, g: 128, b: 0 }, //green
  // { r: 135, g: 206, b: 235 }, //skyblue
  // { r: 250, g: 255, b: 89 }, //yellow
  // { r: 255, g: 192, b: 203 }, //pink
  // { r: 165, g: 42, b: 42 }, //brown
  { r: 168, g: 5, b: 5 },
  { r: 106, g: 1, b: 1 },
  { r: 80, g: 31, b: 31 },
  // { r: 0, g: 2, b: 121 },
  // { r: 121, g: 55, b: 0 },
];

class App {
  constructor() {
    this.canvas = document.createElement("canvas");
    document.body.appendChild(this.canvas);
    this.ctx = this.canvas.getContext("2d");

    this.pixelRatio = window.devicePixelRatio > 1 ? 2 : 1;

    this.totalParticles = 15;
    this.particles = [];
    this.maxRadius = 500;
    this.minRadius = 400;

    window.addEventListener("resize", this.resize.bind(this), false);
    this.resize();

    window.requestAnimationFrame(this.animate.bind(this));
  }

  resize() {
    this.stageWidth = document.body.clientWidth;
    this.stageHeight = document.body.clientHeight;

    this.canvas.width = this.stageWidth * this.pixelRatio;
    this.canvas.height = this.stageHeight * this.pixelRatio;
    this.ctx.scale(this.pixelRatio, this.pixelRatio);

    this.ctx.globalCompositeOperation = "saturation";

    this.createParticles();
  }

  createParticles() {
    let curColor = 0;
    this.particles = [];

    for (let i = 0; i < this.totalParticles; i++) {
      const item = new GlowParticle(
        Math.random() * this.stageWidth,
        Math.random() * this.stageHeight,
        Math.random() * (this.maxRadius - this.minRadius) + this.minRadius,
        COLORS[curColor]
      );

      if (++curColor >= COLORS.length) {
        curColor = 0;
      }

      this.particles[i] = item;
    }
  }

  animate() {
    window.requestAnimationFrame(this.animate.bind(this));

    this.ctx.clearRect(0, 0, this.stageWidth, this.stageHeight);

    for (let i = 0; i < this.totalParticles; i++) {
      const item = this.particles[i];
      item.animate(this.ctx, this.stageWidth, this.stageHeight);
    }
  }
}

window.onload = () => {
  new App();
};
