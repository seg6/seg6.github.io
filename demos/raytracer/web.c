#include <stdint.h>

#include <canvas.h>
#include <vec.h>

#include <array.h>
#include <camera.h>
#include <scene.h>
#include <sphere.h>

static Canvas canvas;
static Scene scene;
static int ready = 0;

__attribute__((export_name("setup")))
void setup(uint32_t width, uint32_t height) {
    if (ready) {
        scene_free(&scene);
        canvas_free(&canvas);
    }

    float camera_hview = 1.0;
    float aspect_ratio = (float)width / (float)height;

    canvas = canvas_new(width, height);
    scene = scene_new(camera_new(0, 0, 0),
                      viewport_new(camera_hview * aspect_ratio, camera_hview, 1),
                      color_rgb(0x6495ed));

    scene_add_light(&scene, light_new_ambient(0.2));
    scene_add_light(&scene, light_new_point(0.8, vec3_new(0, 1, 3)));

    scene_add_object(
        &scene, sphere_new(1, vec3_new(0, -1, 3), color_rgb(0xff0000), 500, 0.2));
    scene_add_object(
        &scene, sphere_new(1, vec3_new(-2, 0, 4), color_rgb(0x00ff00), 10, 0.3));
    scene_add_object(
        &scene, sphere_new(1, vec3_new(2, 0, 4), color_rgb(0x0000ff), 500, 0.5));
    scene_add_object(
        &scene, sphere_new(5000, vec3_new(0, -5001, 0), color_rgb(0xffffff), 1000, 0.5));

    ready = 1;
}

__attribute__((export_name("render")))
Color *render(float cam_x, float cam_y, float cam_z,
              float light_x, float light_y, float light_z, int recursion_limit) {
    scene.cam.pos = vec3_new(cam_x, cam_y, cam_z);
    scene.lights.values[1].position = vec3_new(light_x, light_y, light_z);

    scene_render(&scene, &canvas, recursion_limit);

    return canvas.image.pixel_data;
}

__attribute__((export_name("move_sphere")))
void move_sphere(int index, float x, float y, float z) {
    if (index >= 0 && index < scene.objects.num)
        scene.objects.values[index].pos = vec3_new(x, y, z);
}
