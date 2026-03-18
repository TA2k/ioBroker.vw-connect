.class public final Lcom/google/android/filament/utils/ModelViewer$addDetachListener$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/View$OnAttachStateChangeListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/google/android/filament/utils/ModelViewer;->addDetachListener(Landroid/view/View;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0017\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0004*\u0001\u0000\u0008\n\u0018\u00002\u00020\u0001J\u0017\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0016\u00a2\u0006\u0004\u0008\u0005\u0010\u0006J\u0017\u0010\u0007\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0016\u00a2\u0006\u0004\u0008\u0007\u0010\u0006\u00a8\u0006\u0008"
    }
    d2 = {
        "com/google/android/filament/utils/ModelViewer$addDetachListener$1",
        "Landroid/view/View$OnAttachStateChangeListener;",
        "Landroid/view/View;",
        "v",
        "Llx0/b0;",
        "onViewAttachedToWindow",
        "(Landroid/view/View;)V",
        "onViewDetachedFromWindow",
        "filament-utils-android_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field final synthetic this$0:Lcom/google/android/filament/utils/ModelViewer;


# direct methods
.method public constructor <init>(Lcom/google/android/filament/utils/ModelViewer;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/utils/ModelViewer$addDetachListener$1;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public onViewAttachedToWindow(Landroid/view/View;)V
    .locals 0

    .line 1
    const-string p0, "v"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public onViewDetachedFromWindow(Landroid/view/View;)V
    .locals 1

    .line 1
    const-string v0, "v"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Lcom/google/android/filament/utils/ModelViewer$addDetachListener$1;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 7
    .line 8
    invoke-static {p1}, Lcom/google/android/filament/utils/ModelViewer;->access$getUiHelper$p(Lcom/google/android/filament/utils/ModelViewer;)Lcom/google/android/filament/android/UiHelper;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    invoke-virtual {p1}, Lcom/google/android/filament/android/UiHelper;->detach()V

    .line 13
    .line 14
    .line 15
    iget-object p1, p0, Lcom/google/android/filament/utils/ModelViewer$addDetachListener$1;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 16
    .line 17
    invoke-virtual {p1}, Lcom/google/android/filament/utils/ModelViewer;->destroyModel()V

    .line 18
    .line 19
    .line 20
    iget-object p1, p0, Lcom/google/android/filament/utils/ModelViewer$addDetachListener$1;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 21
    .line 22
    invoke-static {p1}, Lcom/google/android/filament/utils/ModelViewer;->access$getAssetLoader$p(Lcom/google/android/filament/utils/ModelViewer;)Lcom/google/android/filament/gltfio/AssetLoader;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    invoke-virtual {p1}, Lcom/google/android/filament/gltfio/AssetLoader;->destroy()V

    .line 27
    .line 28
    .line 29
    iget-object p1, p0, Lcom/google/android/filament/utils/ModelViewer$addDetachListener$1;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 30
    .line 31
    invoke-static {p1}, Lcom/google/android/filament/utils/ModelViewer;->access$getMaterialProvider$p(Lcom/google/android/filament/utils/ModelViewer;)Lcom/google/android/filament/gltfio/MaterialProvider;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    invoke-interface {p1}, Lcom/google/android/filament/gltfio/MaterialProvider;->destroyMaterials()V

    .line 36
    .line 37
    .line 38
    iget-object p1, p0, Lcom/google/android/filament/utils/ModelViewer$addDetachListener$1;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 39
    .line 40
    invoke-static {p1}, Lcom/google/android/filament/utils/ModelViewer;->access$getMaterialProvider$p(Lcom/google/android/filament/utils/ModelViewer;)Lcom/google/android/filament/gltfio/MaterialProvider;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    invoke-interface {p1}, Lcom/google/android/filament/gltfio/MaterialProvider;->destroy()V

    .line 45
    .line 46
    .line 47
    iget-object p1, p0, Lcom/google/android/filament/utils/ModelViewer$addDetachListener$1;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 48
    .line 49
    invoke-static {p1}, Lcom/google/android/filament/utils/ModelViewer;->access$getResourceLoader$p(Lcom/google/android/filament/utils/ModelViewer;)Lcom/google/android/filament/gltfio/ResourceLoader;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    invoke-virtual {p1}, Lcom/google/android/filament/gltfio/ResourceLoader;->destroy()V

    .line 54
    .line 55
    .line 56
    iget-object p1, p0, Lcom/google/android/filament/utils/ModelViewer$addDetachListener$1;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 57
    .line 58
    invoke-virtual {p1}, Lcom/google/android/filament/utils/ModelViewer;->getEngine()Lcom/google/android/filament/Engine;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer$addDetachListener$1;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 63
    .line 64
    invoke-virtual {v0}, Lcom/google/android/filament/utils/ModelViewer;->getLight()I

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    invoke-virtual {p1, v0}, Lcom/google/android/filament/Engine;->destroyEntity(I)V

    .line 69
    .line 70
    .line 71
    iget-object p1, p0, Lcom/google/android/filament/utils/ModelViewer$addDetachListener$1;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 72
    .line 73
    invoke-virtual {p1}, Lcom/google/android/filament/utils/ModelViewer;->getEngine()Lcom/google/android/filament/Engine;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer$addDetachListener$1;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 78
    .line 79
    invoke-virtual {v0}, Lcom/google/android/filament/utils/ModelViewer;->getRenderer()Lcom/google/android/filament/Renderer;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    invoke-virtual {p1, v0}, Lcom/google/android/filament/Engine;->destroyRenderer(Lcom/google/android/filament/Renderer;)V

    .line 84
    .line 85
    .line 86
    iget-object p1, p0, Lcom/google/android/filament/utils/ModelViewer$addDetachListener$1;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 87
    .line 88
    invoke-virtual {p1}, Lcom/google/android/filament/utils/ModelViewer;->getEngine()Lcom/google/android/filament/Engine;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer$addDetachListener$1;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 93
    .line 94
    invoke-virtual {v0}, Lcom/google/android/filament/utils/ModelViewer;->getView()Lcom/google/android/filament/View;

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    invoke-virtual {p1, v0}, Lcom/google/android/filament/Engine;->destroyView(Lcom/google/android/filament/View;)V

    .line 99
    .line 100
    .line 101
    iget-object p1, p0, Lcom/google/android/filament/utils/ModelViewer$addDetachListener$1;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 102
    .line 103
    invoke-virtual {p1}, Lcom/google/android/filament/utils/ModelViewer;->getEngine()Lcom/google/android/filament/Engine;

    .line 104
    .line 105
    .line 106
    move-result-object p1

    .line 107
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer$addDetachListener$1;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 108
    .line 109
    invoke-virtual {v0}, Lcom/google/android/filament/utils/ModelViewer;->getScene()Lcom/google/android/filament/Scene;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    invoke-virtual {p1, v0}, Lcom/google/android/filament/Engine;->destroyScene(Lcom/google/android/filament/Scene;)V

    .line 114
    .line 115
    .line 116
    iget-object p1, p0, Lcom/google/android/filament/utils/ModelViewer$addDetachListener$1;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 117
    .line 118
    invoke-virtual {p1}, Lcom/google/android/filament/utils/ModelViewer;->getEngine()Lcom/google/android/filament/Engine;

    .line 119
    .line 120
    .line 121
    move-result-object p1

    .line 122
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer$addDetachListener$1;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 123
    .line 124
    invoke-virtual {v0}, Lcom/google/android/filament/utils/ModelViewer;->getCamera()Lcom/google/android/filament/Camera;

    .line 125
    .line 126
    .line 127
    move-result-object v0

    .line 128
    invoke-virtual {v0}, Lcom/google/android/filament/Camera;->getEntity()I

    .line 129
    .line 130
    .line 131
    move-result v0

    .line 132
    invoke-virtual {p1, v0}, Lcom/google/android/filament/Engine;->destroyCameraComponent(I)V

    .line 133
    .line 134
    .line 135
    invoke-static {}, Lcom/google/android/filament/EntityManager;->get()Lcom/google/android/filament/EntityManager;

    .line 136
    .line 137
    .line 138
    move-result-object p1

    .line 139
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer$addDetachListener$1;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 140
    .line 141
    invoke-virtual {v0}, Lcom/google/android/filament/utils/ModelViewer;->getCamera()Lcom/google/android/filament/Camera;

    .line 142
    .line 143
    .line 144
    move-result-object v0

    .line 145
    invoke-virtual {v0}, Lcom/google/android/filament/Camera;->getEntity()I

    .line 146
    .line 147
    .line 148
    move-result v0

    .line 149
    invoke-virtual {p1, v0}, Lcom/google/android/filament/EntityManager;->destroy(I)V

    .line 150
    .line 151
    .line 152
    invoke-static {}, Lcom/google/android/filament/EntityManager;->get()Lcom/google/android/filament/EntityManager;

    .line 153
    .line 154
    .line 155
    move-result-object p1

    .line 156
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer$addDetachListener$1;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 157
    .line 158
    invoke-virtual {v0}, Lcom/google/android/filament/utils/ModelViewer;->getLight()I

    .line 159
    .line 160
    .line 161
    move-result v0

    .line 162
    invoke-virtual {p1, v0}, Lcom/google/android/filament/EntityManager;->destroy(I)V

    .line 163
    .line 164
    .line 165
    iget-object p0, p0, Lcom/google/android/filament/utils/ModelViewer$addDetachListener$1;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 166
    .line 167
    invoke-virtual {p0}, Lcom/google/android/filament/utils/ModelViewer;->getEngine()Lcom/google/android/filament/Engine;

    .line 168
    .line 169
    .line 170
    move-result-object p0

    .line 171
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->destroy()V

    .line 172
    .line 173
    .line 174
    return-void
.end method
