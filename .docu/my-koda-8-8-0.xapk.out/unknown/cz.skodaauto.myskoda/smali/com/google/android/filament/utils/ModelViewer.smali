.class public final Lcom/google/android/filament/utils/ModelViewer;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/View$OnTouchListener;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/utils/ModelViewer$Companion;,
        Lcom/google/android/filament/utils/ModelViewer$SurfaceCallback;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u00f4\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0010\t\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0012\n\u0002\u0018\u0002\n\u0002\u0008\n\n\u0002\u0010\u0007\n\u0002\u0008\u000c\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\u0008\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u0015\n\u0002\u0008\u0002\n\u0002\u0010\u0013\n\u0002\u0008\n\u0018\u0000 \u0096\u00012\u00020\u0001:\u0004\u0097\u0001\u0096\u0001B\u0017\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u00a2\u0006\u0004\u0008\u0006\u0010\u0007B1\u0008\u0016\u0012\u0006\u0010\t\u001a\u00020\u0008\u0012\u0008\u0008\u0002\u0010\u0003\u001a\u00020\u0002\u0012\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u0004\u0012\n\u0008\u0002\u0010\u000b\u001a\u0004\u0018\u00010\n\u00a2\u0006\u0004\u0008\u0006\u0010\u000cB1\u0008\u0016\u0012\u0006\u0010\u000e\u001a\u00020\r\u0012\u0008\u0008\u0002\u0010\u0003\u001a\u00020\u0002\u0012\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u0004\u0012\n\u0008\u0002\u0010\u000b\u001a\u0004\u0018\u00010\n\u00a2\u0006\u0004\u0008\u0006\u0010\u000fJ\u0015\u0010\u0013\u001a\u00020\u00122\u0006\u0010\u0011\u001a\u00020\u0010\u00a2\u0006\u0004\u0008\u0013\u0010\u0014J+\u0010\u0018\u001a\u00020\u00122\u0006\u0010\u0011\u001a\u00020\u00102\u0014\u0010\u0017\u001a\u0010\u0012\u0004\u0012\u00020\u0016\u0012\u0006\u0012\u0004\u0018\u00010\u00100\u0015\u00a2\u0006\u0004\u0008\u0018\u0010\u0019J)\u0010\u001a\u001a\u00020\u00122\u0006\u0010\u0011\u001a\u00020\u00102\u0012\u0010\u0017\u001a\u000e\u0012\u0004\u0012\u00020\u0016\u0012\u0004\u0012\u00020\u00100\u0015\u00a2\u0006\u0004\u0008\u001a\u0010\u0019J\u0017\u0010\u001d\u001a\u00020\u00122\u0008\u0008\u0002\u0010\u001c\u001a\u00020\u001b\u00a2\u0006\u0004\u0008\u001d\u0010\u001eJ\r\u0010\u001f\u001a\u00020\u0012\u00a2\u0006\u0004\u0008\u001f\u0010 J\r\u0010!\u001a\u00020\u0012\u00a2\u0006\u0004\u0008!\u0010 J\u0015\u0010$\u001a\u00020\u00122\u0006\u0010#\u001a\u00020\"\u00a2\u0006\u0004\u0008$\u0010%J\u0015\u0010(\u001a\u00020\u00122\u0006\u0010\'\u001a\u00020&\u00a2\u0006\u0004\u0008(\u0010)J\u001f\u0010-\u001a\u00020,2\u0006\u0010+\u001a\u00020*2\u0006\u0010\'\u001a\u00020&H\u0016\u00a2\u0006\u0004\u0008-\u0010.J\u0017\u00101\u001a\u00020\u00122\u0006\u00100\u001a\u00020/H\u0002\u00a2\u0006\u0004\u00081\u00102J\u0017\u00103\u001a\u00020\u00122\u0006\u0010+\u001a\u00020*H\u0002\u00a2\u0006\u0004\u00083\u00104J,\u00105\u001a\u00020\u00122\u0006\u00100\u001a\u00020/2\u0012\u0010\u0017\u001a\u000e\u0012\u0004\u0012\u00020\u0016\u0012\u0004\u0012\u00020\u00100\u0015H\u0082@\u00a2\u0006\u0004\u00085\u00106J\u000f\u00107\u001a\u00020\u0012H\u0002\u00a2\u0006\u0004\u00087\u0010 J\u0017\u00108\u001a\u00020\u00122\u0006\u0010\u0003\u001a\u00020\u0002H\u0002\u00a2\u0006\u0004\u00088\u00109R\u0017\u0010\u0003\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0003\u0010:\u001a\u0004\u0008;\u0010<R\u0014\u0010\u0005\u001a\u00020\u00048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0005\u0010=R(\u00100\u001a\u0004\u0018\u00010/2\u0008\u0010>\u001a\u0004\u0018\u00010/8\u0006@BX\u0086\u000e\u00a2\u0006\u000c\n\u0004\u00080\u0010?\u001a\u0004\u0008@\u0010AR(\u0010C\u001a\u0004\u0018\u00010B2\u0008\u0010>\u001a\u0004\u0018\u00010B8\u0006@BX\u0086\u000e\u00a2\u0006\u000c\n\u0004\u0008C\u0010D\u001a\u0004\u0008E\u0010FR\"\u0010G\u001a\u00020,8\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008G\u0010H\u001a\u0004\u0008I\u0010J\"\u0004\u0008K\u0010LR*\u0010N\u001a\u00020M2\u0006\u0010>\u001a\u00020M8\u0006@FX\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008N\u0010O\u001a\u0004\u0008P\u0010Q\"\u0004\u0008R\u0010SR*\u0010T\u001a\u00020M2\u0006\u0010>\u001a\u00020M8\u0006@FX\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008T\u0010O\u001a\u0004\u0008U\u0010Q\"\u0004\u0008V\u0010SR*\u0010W\u001a\u00020M2\u0006\u0010>\u001a\u00020M8\u0006@FX\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008W\u0010O\u001a\u0004\u0008X\u0010Q\"\u0004\u0008Y\u0010SR\u0017\u0010[\u001a\u00020Z8\u0006\u00a2\u0006\u000c\n\u0004\u0008[\u0010\\\u001a\u0004\u0008]\u0010^R\u0017\u0010+\u001a\u00020_8\u0006\u00a2\u0006\u000c\n\u0004\u0008+\u0010`\u001a\u0004\u0008a\u0010bR\u0017\u0010d\u001a\u00020c8\u0006\u00a2\u0006\u000c\n\u0004\u0008d\u0010e\u001a\u0004\u0008f\u0010gR\u0017\u0010i\u001a\u00020h8\u0006\u00a2\u0006\u000c\n\u0004\u0008i\u0010j\u001a\u0004\u0008k\u0010lR\u001a\u0010n\u001a\u00020m8\u0006X\u0087\u0004\u00a2\u0006\u000c\n\u0004\u0008n\u0010o\u001a\u0004\u0008p\u0010qR\u0016\u0010s\u001a\u00020r8\u0002@\u0002X\u0082.\u00a2\u0006\u0006\n\u0004\u0008s\u0010tR\u0016\u0010u\u001a\u00020\n8\u0002@\u0002X\u0082.\u00a2\u0006\u0006\n\u0004\u0008u\u0010vR\u0016\u0010x\u001a\u00020w8\u0002@\u0002X\u0082.\u00a2\u0006\u0006\n\u0004\u0008x\u0010yR\u0018\u0010\t\u001a\u0004\u0018\u00010\u00088\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008\t\u0010zR\u0018\u0010\u000e\u001a\u0004\u0018\u00010\r8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008\u000e\u0010{R\u0018\u0010}\u001a\u0004\u0018\u00010|8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008}\u0010~R\u001b\u0010\u0080\u0001\u001a\u0004\u0018\u00010\u007f8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0008\n\u0006\u0008\u0080\u0001\u0010\u0081\u0001R\u001a\u0010\u0083\u0001\u001a\u00030\u0082\u00018\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0008\n\u0006\u0008\u0083\u0001\u0010\u0084\u0001R\u001a\u0010\u0086\u0001\u001a\u00030\u0085\u00018\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0008\n\u0006\u0008\u0086\u0001\u0010\u0087\u0001R\u001a\u0010\u0089\u0001\u001a\u00030\u0088\u00018\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0008\n\u0006\u0008\u0089\u0001\u0010\u008a\u0001R\u0018\u0010\u008c\u0001\u001a\u00030\u008b\u00018\u0002X\u0082\u0004\u00a2\u0006\u0008\n\u0006\u0008\u008c\u0001\u0010\u008d\u0001R\u0018\u0010\u008f\u0001\u001a\u00030\u008e\u00018\u0002X\u0082\u0004\u00a2\u0006\u0008\n\u0006\u0008\u008f\u0001\u0010\u0090\u0001R\u0018\u0010\u0091\u0001\u001a\u00030\u008e\u00018\u0002X\u0082\u0004\u00a2\u0006\u0008\n\u0006\u0008\u0091\u0001\u0010\u0090\u0001R\u0018\u0010\u0092\u0001\u001a\u00030\u008e\u00018\u0002X\u0082\u0004\u00a2\u0006\u0008\n\u0006\u0008\u0092\u0001\u0010\u0090\u0001R\u001a\u0010\u0095\u0001\u001a\u00020M8F\u00a2\u0006\u000e\u0012\u0005\u0008\u0094\u0001\u0010 \u001a\u0005\u0008\u0093\u0001\u0010Q\u00a8\u0006\u0098\u0001"
    }
    d2 = {
        "Lcom/google/android/filament/utils/ModelViewer;",
        "Landroid/view/View$OnTouchListener;",
        "Lcom/google/android/filament/Engine;",
        "engine",
        "Lcom/google/android/filament/android/UiHelper;",
        "uiHelper",
        "<init>",
        "(Lcom/google/android/filament/Engine;Lcom/google/android/filament/android/UiHelper;)V",
        "Landroid/view/SurfaceView;",
        "surfaceView",
        "Lcom/google/android/filament/utils/Manipulator;",
        "manipulator",
        "(Landroid/view/SurfaceView;Lcom/google/android/filament/Engine;Lcom/google/android/filament/android/UiHelper;Lcom/google/android/filament/utils/Manipulator;)V",
        "Landroid/view/TextureView;",
        "textureView",
        "(Landroid/view/TextureView;Lcom/google/android/filament/Engine;Lcom/google/android/filament/android/UiHelper;Lcom/google/android/filament/utils/Manipulator;)V",
        "Ljava/nio/Buffer;",
        "buffer",
        "Llx0/b0;",
        "loadModelGlb",
        "(Ljava/nio/Buffer;)V",
        "Lkotlin/Function1;",
        "",
        "callback",
        "loadModelGltf",
        "(Ljava/nio/Buffer;Lay0/k;)V",
        "loadModelGltfAsync",
        "Lcom/google/android/filament/utils/Float3;",
        "centerPoint",
        "transformToUnitCube",
        "(Lcom/google/android/filament/utils/Float3;)V",
        "clearRootTransform",
        "()V",
        "destroyModel",
        "",
        "frameTimeNanos",
        "render",
        "(J)V",
        "Landroid/view/MotionEvent;",
        "event",
        "onTouchEvent",
        "(Landroid/view/MotionEvent;)V",
        "Landroid/view/View;",
        "view",
        "",
        "onTouch",
        "(Landroid/view/View;Landroid/view/MotionEvent;)Z",
        "Lcom/google/android/filament/gltfio/FilamentAsset;",
        "asset",
        "populateScene",
        "(Lcom/google/android/filament/gltfio/FilamentAsset;)V",
        "addDetachListener",
        "(Landroid/view/View;)V",
        "fetchResources",
        "(Lcom/google/android/filament/gltfio/FilamentAsset;Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "updateCameraProjection",
        "synchronizePendingFrames",
        "(Lcom/google/android/filament/Engine;)V",
        "Lcom/google/android/filament/Engine;",
        "getEngine",
        "()Lcom/google/android/filament/Engine;",
        "Lcom/google/android/filament/android/UiHelper;",
        "value",
        "Lcom/google/android/filament/gltfio/FilamentAsset;",
        "getAsset",
        "()Lcom/google/android/filament/gltfio/FilamentAsset;",
        "Lcom/google/android/filament/gltfio/Animator;",
        "animator",
        "Lcom/google/android/filament/gltfio/Animator;",
        "getAnimator",
        "()Lcom/google/android/filament/gltfio/Animator;",
        "normalizeSkinningWeights",
        "Z",
        "getNormalizeSkinningWeights",
        "()Z",
        "setNormalizeSkinningWeights",
        "(Z)V",
        "",
        "cameraFocalLength",
        "F",
        "getCameraFocalLength",
        "()F",
        "setCameraFocalLength",
        "(F)V",
        "cameraNear",
        "getCameraNear",
        "setCameraNear",
        "cameraFar",
        "getCameraFar",
        "setCameraFar",
        "Lcom/google/android/filament/Scene;",
        "scene",
        "Lcom/google/android/filament/Scene;",
        "getScene",
        "()Lcom/google/android/filament/Scene;",
        "Lcom/google/android/filament/View;",
        "Lcom/google/android/filament/View;",
        "getView",
        "()Lcom/google/android/filament/View;",
        "Lcom/google/android/filament/Camera;",
        "camera",
        "Lcom/google/android/filament/Camera;",
        "getCamera",
        "()Lcom/google/android/filament/Camera;",
        "Lcom/google/android/filament/Renderer;",
        "renderer",
        "Lcom/google/android/filament/Renderer;",
        "getRenderer",
        "()Lcom/google/android/filament/Renderer;",
        "",
        "light",
        "I",
        "getLight",
        "()I",
        "Lcom/google/android/filament/android/DisplayHelper;",
        "displayHelper",
        "Lcom/google/android/filament/android/DisplayHelper;",
        "cameraManipulator",
        "Lcom/google/android/filament/utils/Manipulator;",
        "Lcom/google/android/filament/utils/GestureDetector;",
        "gestureDetector",
        "Lcom/google/android/filament/utils/GestureDetector;",
        "Landroid/view/SurfaceView;",
        "Landroid/view/TextureView;",
        "Lvy0/i1;",
        "fetchResourcesJob",
        "Lvy0/i1;",
        "Lcom/google/android/filament/SwapChain;",
        "swapChain",
        "Lcom/google/android/filament/SwapChain;",
        "Lcom/google/android/filament/gltfio/AssetLoader;",
        "assetLoader",
        "Lcom/google/android/filament/gltfio/AssetLoader;",
        "Lcom/google/android/filament/gltfio/MaterialProvider;",
        "materialProvider",
        "Lcom/google/android/filament/gltfio/MaterialProvider;",
        "Lcom/google/android/filament/gltfio/ResourceLoader;",
        "resourceLoader",
        "Lcom/google/android/filament/gltfio/ResourceLoader;",
        "",
        "readyRenderables",
        "[I",
        "",
        "eyePos",
        "[D",
        "target",
        "upward",
        "getProgress",
        "getProgress$annotations",
        "progress",
        "Companion",
        "SurfaceCallback",
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


# static fields
.field public static final Companion:Lcom/google/android/filament/utils/ModelViewer$Companion;

.field private static final kDefaultObjectPosition:Lcom/google/android/filament/utils/Float3;


# instance fields
.field private animator:Lcom/google/android/filament/gltfio/Animator;

.field private asset:Lcom/google/android/filament/gltfio/FilamentAsset;

.field private assetLoader:Lcom/google/android/filament/gltfio/AssetLoader;

.field private final camera:Lcom/google/android/filament/Camera;

.field private cameraFar:F

.field private cameraFocalLength:F

.field private cameraManipulator:Lcom/google/android/filament/utils/Manipulator;

.field private cameraNear:F

.field private displayHelper:Lcom/google/android/filament/android/DisplayHelper;

.field private final engine:Lcom/google/android/filament/Engine;

.field private final eyePos:[D

.field private fetchResourcesJob:Lvy0/i1;

.field private gestureDetector:Lcom/google/android/filament/utils/GestureDetector;

.field private final light:I
    .annotation build Lcom/google/android/filament/Entity;
    .end annotation
.end field

.field private materialProvider:Lcom/google/android/filament/gltfio/MaterialProvider;

.field private normalizeSkinningWeights:Z

.field private final readyRenderables:[I

.field private final renderer:Lcom/google/android/filament/Renderer;

.field private resourceLoader:Lcom/google/android/filament/gltfio/ResourceLoader;

.field private final scene:Lcom/google/android/filament/Scene;

.field private surfaceView:Landroid/view/SurfaceView;

.field private swapChain:Lcom/google/android/filament/SwapChain;

.field private final target:[D

.field private textureView:Landroid/view/TextureView;

.field private final uiHelper:Lcom/google/android/filament/android/UiHelper;

.field private final upward:[D

.field private final view:Lcom/google/android/filament/View;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/ModelViewer$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/google/android/filament/utils/ModelViewer$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/google/android/filament/utils/ModelViewer;->Companion:Lcom/google/android/filament/utils/ModelViewer$Companion;

    .line 8
    .line 9
    new-instance v0, Lcom/google/android/filament/utils/Float3;

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    const/high16 v2, -0x3f800000    # -4.0f

    .line 13
    .line 14
    invoke-direct {v0, v1, v1, v2}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lcom/google/android/filament/utils/ModelViewer;->kDefaultObjectPosition:Lcom/google/android/filament/utils/Float3;

    .line 18
    .line 19
    return-void
.end method

.method public constructor <init>(Landroid/view/SurfaceView;Lcom/google/android/filament/Engine;Lcom/google/android/filament/android/UiHelper;Lcom/google/android/filament/utils/Manipulator;)V
    .locals 2

    const-string v0, "surfaceView"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "engine"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "uiHelper"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    invoke-direct {p0, p2, p3}, Lcom/google/android/filament/utils/ModelViewer;-><init>(Lcom/google/android/filament/Engine;Lcom/google/android/filament/android/UiHelper;)V

    if-nez p4, :cond_0

    .line 34
    new-instance p2, Lcom/google/android/filament/utils/Manipulator$Builder;

    invoke-direct {p2}, Lcom/google/android/filament/utils/Manipulator$Builder;-><init>()V

    .line 35
    sget-object p4, Lcom/google/android/filament/utils/ModelViewer;->kDefaultObjectPosition:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {p4}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v0

    invoke-virtual {p4}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v1

    invoke-virtual {p4}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result p4

    invoke-virtual {p2, v0, v1, p4}, Lcom/google/android/filament/utils/Manipulator$Builder;->targetPosition(FFF)Lcom/google/android/filament/utils/Manipulator$Builder;

    move-result-object p2

    .line 36
    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    move-result p4

    invoke-virtual {p1}, Landroid/view/View;->getHeight()I

    move-result v0

    invoke-virtual {p2, p4, v0}, Lcom/google/android/filament/utils/Manipulator$Builder;->viewport(II)Lcom/google/android/filament/utils/Manipulator$Builder;

    move-result-object p2

    .line 37
    sget-object p4, Lcom/google/android/filament/utils/Manipulator$Mode;->ORBIT:Lcom/google/android/filament/utils/Manipulator$Mode;

    invoke-virtual {p2, p4}, Lcom/google/android/filament/utils/Manipulator$Builder;->build(Lcom/google/android/filament/utils/Manipulator$Mode;)Lcom/google/android/filament/utils/Manipulator;

    move-result-object p4

    const-string p2, "build(...)"

    invoke-static {p4, p2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 38
    :cond_0
    iput-object p4, p0, Lcom/google/android/filament/utils/ModelViewer;->cameraManipulator:Lcom/google/android/filament/utils/Manipulator;

    .line 39
    iput-object p1, p0, Lcom/google/android/filament/utils/ModelViewer;->surfaceView:Landroid/view/SurfaceView;

    .line 40
    new-instance p2, Lcom/google/android/filament/utils/GestureDetector;

    invoke-direct {p2, p1, p4}, Lcom/google/android/filament/utils/GestureDetector;-><init>(Landroid/view/View;Lcom/google/android/filament/utils/Manipulator;)V

    iput-object p2, p0, Lcom/google/android/filament/utils/ModelViewer;->gestureDetector:Lcom/google/android/filament/utils/GestureDetector;

    .line 41
    new-instance p2, Lcom/google/android/filament/android/DisplayHelper;

    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object p4

    invoke-direct {p2, p4}, Lcom/google/android/filament/android/DisplayHelper;-><init>(Landroid/content/Context;)V

    iput-object p2, p0, Lcom/google/android/filament/utils/ModelViewer;->displayHelper:Lcom/google/android/filament/android/DisplayHelper;

    .line 42
    new-instance p2, Lcom/google/android/filament/utils/ModelViewer$SurfaceCallback;

    invoke-direct {p2, p0}, Lcom/google/android/filament/utils/ModelViewer$SurfaceCallback;-><init>(Lcom/google/android/filament/utils/ModelViewer;)V

    invoke-virtual {p3, p2}, Lcom/google/android/filament/android/UiHelper;->setRenderCallback(Lcom/google/android/filament/android/UiHelper$RendererCallback;)V

    .line 43
    invoke-virtual {p3, p1}, Lcom/google/android/filament/android/UiHelper;->attachTo(Landroid/view/SurfaceView;)V

    .line 44
    invoke-direct {p0, p1}, Lcom/google/android/filament/utils/ModelViewer;->addDetachListener(Landroid/view/View;)V

    return-void
.end method

.method public synthetic constructor <init>(Landroid/view/SurfaceView;Lcom/google/android/filament/Engine;Lcom/google/android/filament/android/UiHelper;Lcom/google/android/filament/utils/Manipulator;ILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p6, p5, 0x2

    if-eqz p6, :cond_0

    .line 30
    invoke-static {}, Lcom/google/android/filament/Engine;->create()Lcom/google/android/filament/Engine;

    move-result-object p2

    :cond_0
    and-int/lit8 p6, p5, 0x4

    if-eqz p6, :cond_1

    .line 31
    new-instance p3, Lcom/google/android/filament/android/UiHelper;

    sget-object p6, Lcom/google/android/filament/android/UiHelper$ContextErrorPolicy;->DONT_CHECK:Lcom/google/android/filament/android/UiHelper$ContextErrorPolicy;

    invoke-direct {p3, p6}, Lcom/google/android/filament/android/UiHelper;-><init>(Lcom/google/android/filament/android/UiHelper$ContextErrorPolicy;)V

    :cond_1
    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_2

    const/4 p4, 0x0

    .line 32
    :cond_2
    invoke-direct {p0, p1, p2, p3, p4}, Lcom/google/android/filament/utils/ModelViewer;-><init>(Landroid/view/SurfaceView;Lcom/google/android/filament/Engine;Lcom/google/android/filament/android/UiHelper;Lcom/google/android/filament/utils/Manipulator;)V

    return-void
.end method

.method public constructor <init>(Landroid/view/TextureView;Lcom/google/android/filament/Engine;Lcom/google/android/filament/android/UiHelper;Lcom/google/android/filament/utils/Manipulator;)V
    .locals 2

    const-string v0, "textureView"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "engine"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "uiHelper"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 48
    invoke-direct {p0, p2, p3}, Lcom/google/android/filament/utils/ModelViewer;-><init>(Lcom/google/android/filament/Engine;Lcom/google/android/filament/android/UiHelper;)V

    if-nez p4, :cond_0

    .line 49
    new-instance p2, Lcom/google/android/filament/utils/Manipulator$Builder;

    invoke-direct {p2}, Lcom/google/android/filament/utils/Manipulator$Builder;-><init>()V

    .line 50
    sget-object p4, Lcom/google/android/filament/utils/ModelViewer;->kDefaultObjectPosition:Lcom/google/android/filament/utils/Float3;

    invoke-virtual {p4}, Lcom/google/android/filament/utils/Float3;->getX()F

    move-result v0

    invoke-virtual {p4}, Lcom/google/android/filament/utils/Float3;->getY()F

    move-result v1

    invoke-virtual {p4}, Lcom/google/android/filament/utils/Float3;->getZ()F

    move-result p4

    invoke-virtual {p2, v0, v1, p4}, Lcom/google/android/filament/utils/Manipulator$Builder;->targetPosition(FFF)Lcom/google/android/filament/utils/Manipulator$Builder;

    move-result-object p2

    .line 51
    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    move-result p4

    invoke-virtual {p1}, Landroid/view/View;->getHeight()I

    move-result v0

    invoke-virtual {p2, p4, v0}, Lcom/google/android/filament/utils/Manipulator$Builder;->viewport(II)Lcom/google/android/filament/utils/Manipulator$Builder;

    move-result-object p2

    .line 52
    sget-object p4, Lcom/google/android/filament/utils/Manipulator$Mode;->ORBIT:Lcom/google/android/filament/utils/Manipulator$Mode;

    invoke-virtual {p2, p4}, Lcom/google/android/filament/utils/Manipulator$Builder;->build(Lcom/google/android/filament/utils/Manipulator$Mode;)Lcom/google/android/filament/utils/Manipulator;

    move-result-object p4

    const-string p2, "build(...)"

    invoke-static {p4, p2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 53
    :cond_0
    iput-object p4, p0, Lcom/google/android/filament/utils/ModelViewer;->cameraManipulator:Lcom/google/android/filament/utils/Manipulator;

    .line 54
    iput-object p1, p0, Lcom/google/android/filament/utils/ModelViewer;->textureView:Landroid/view/TextureView;

    .line 55
    new-instance p2, Lcom/google/android/filament/utils/GestureDetector;

    invoke-direct {p2, p1, p4}, Lcom/google/android/filament/utils/GestureDetector;-><init>(Landroid/view/View;Lcom/google/android/filament/utils/Manipulator;)V

    iput-object p2, p0, Lcom/google/android/filament/utils/ModelViewer;->gestureDetector:Lcom/google/android/filament/utils/GestureDetector;

    .line 56
    new-instance p2, Lcom/google/android/filament/android/DisplayHelper;

    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object p4

    invoke-direct {p2, p4}, Lcom/google/android/filament/android/DisplayHelper;-><init>(Landroid/content/Context;)V

    iput-object p2, p0, Lcom/google/android/filament/utils/ModelViewer;->displayHelper:Lcom/google/android/filament/android/DisplayHelper;

    .line 57
    new-instance p2, Lcom/google/android/filament/utils/ModelViewer$SurfaceCallback;

    invoke-direct {p2, p0}, Lcom/google/android/filament/utils/ModelViewer$SurfaceCallback;-><init>(Lcom/google/android/filament/utils/ModelViewer;)V

    invoke-virtual {p3, p2}, Lcom/google/android/filament/android/UiHelper;->setRenderCallback(Lcom/google/android/filament/android/UiHelper$RendererCallback;)V

    .line 58
    invoke-virtual {p3, p1}, Lcom/google/android/filament/android/UiHelper;->attachTo(Landroid/view/TextureView;)V

    .line 59
    invoke-direct {p0, p1}, Lcom/google/android/filament/utils/ModelViewer;->addDetachListener(Landroid/view/View;)V

    return-void
.end method

.method public synthetic constructor <init>(Landroid/view/TextureView;Lcom/google/android/filament/Engine;Lcom/google/android/filament/android/UiHelper;Lcom/google/android/filament/utils/Manipulator;ILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p6, p5, 0x2

    if-eqz p6, :cond_0

    .line 45
    invoke-static {}, Lcom/google/android/filament/Engine;->create()Lcom/google/android/filament/Engine;

    move-result-object p2

    :cond_0
    and-int/lit8 p6, p5, 0x4

    if-eqz p6, :cond_1

    .line 46
    new-instance p3, Lcom/google/android/filament/android/UiHelper;

    sget-object p6, Lcom/google/android/filament/android/UiHelper$ContextErrorPolicy;->DONT_CHECK:Lcom/google/android/filament/android/UiHelper$ContextErrorPolicy;

    invoke-direct {p3, p6}, Lcom/google/android/filament/android/UiHelper;-><init>(Lcom/google/android/filament/android/UiHelper$ContextErrorPolicy;)V

    :cond_1
    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_2

    const/4 p4, 0x0

    .line 47
    :cond_2
    invoke-direct {p0, p1, p2, p3, p4}, Lcom/google/android/filament/utils/ModelViewer;-><init>(Landroid/view/TextureView;Lcom/google/android/filament/Engine;Lcom/google/android/filament/android/UiHelper;Lcom/google/android/filament/utils/Manipulator;)V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/filament/Engine;Lcom/google/android/filament/android/UiHelper;)V
    .locals 6

    const-string v0, "engine"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "uiHelper"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcom/google/android/filament/utils/ModelViewer;->engine:Lcom/google/android/filament/Engine;

    .line 3
    iput-object p2, p0, Lcom/google/android/filament/utils/ModelViewer;->uiHelper:Lcom/google/android/filament/android/UiHelper;

    const/4 p2, 0x1

    .line 4
    iput-boolean p2, p0, Lcom/google/android/filament/utils/ModelViewer;->normalizeSkinningWeights:Z

    const/high16 v0, 0x41e00000    # 28.0f

    .line 5
    iput v0, p0, Lcom/google/android/filament/utils/ModelViewer;->cameraFocalLength:F

    const v0, 0x3d4ccccd    # 0.05f

    .line 6
    iput v0, p0, Lcom/google/android/filament/utils/ModelViewer;->cameraNear:F

    const/high16 v0, 0x447a0000    # 1000.0f

    .line 7
    iput v0, p0, Lcom/google/android/filament/utils/ModelViewer;->cameraFar:F

    const/16 v0, 0x80

    .line 8
    new-array v0, v0, [I

    iput-object v0, p0, Lcom/google/android/filament/utils/ModelViewer;->readyRenderables:[I

    const/4 v0, 0x3

    .line 9
    new-array v1, v0, [D

    iput-object v1, p0, Lcom/google/android/filament/utils/ModelViewer;->eyePos:[D

    .line 10
    new-array v1, v0, [D

    iput-object v1, p0, Lcom/google/android/filament/utils/ModelViewer;->target:[D

    .line 11
    new-array v0, v0, [D

    iput-object v0, p0, Lcom/google/android/filament/utils/ModelViewer;->upward:[D

    .line 12
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->createRenderer()Lcom/google/android/filament/Renderer;

    move-result-object v0

    iput-object v0, p0, Lcom/google/android/filament/utils/ModelViewer;->renderer:Lcom/google/android/filament/Renderer;

    .line 13
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->createScene()Lcom/google/android/filament/Scene;

    move-result-object v0

    iput-object v0, p0, Lcom/google/android/filament/utils/ModelViewer;->scene:Lcom/google/android/filament/Scene;

    .line 14
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getEntityManager()Lcom/google/android/filament/EntityManager;

    move-result-object v1

    invoke-virtual {v1}, Lcom/google/android/filament/EntityManager;->create()I

    move-result v1

    invoke-virtual {p1, v1}, Lcom/google/android/filament/Engine;->createCamera(I)Lcom/google/android/filament/Camera;

    move-result-object v1

    const-string v2, "createCamera(...)"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const v2, 0x3c03126f    # 0.008f

    const/high16 v3, 0x42c80000    # 100.0f

    const/high16 v4, 0x41800000    # 16.0f

    invoke-virtual {v1, v4, v2, v3}, Lcom/google/android/filament/Camera;->setExposure(FFF)V

    iput-object v1, p0, Lcom/google/android/filament/utils/ModelViewer;->camera:Lcom/google/android/filament/Camera;

    .line 15
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->createView()Lcom/google/android/filament/View;

    move-result-object v2

    iput-object v2, p0, Lcom/google/android/filament/utils/ModelViewer;->view:Lcom/google/android/filament/View;

    .line 16
    invoke-virtual {v2, v0}, Lcom/google/android/filament/View;->setScene(Lcom/google/android/filament/Scene;)V

    .line 17
    invoke-virtual {v2, v1}, Lcom/google/android/filament/View;->setCamera(Lcom/google/android/filament/Camera;)V

    .line 18
    new-instance v1, Lcom/google/android/filament/gltfio/UbershaderProvider;

    invoke-direct {v1, p1}, Lcom/google/android/filament/gltfio/UbershaderProvider;-><init>(Lcom/google/android/filament/Engine;)V

    iput-object v1, p0, Lcom/google/android/filament/utils/ModelViewer;->materialProvider:Lcom/google/android/filament/gltfio/MaterialProvider;

    .line 19
    new-instance v2, Lcom/google/android/filament/gltfio/AssetLoader;

    invoke-static {}, Lcom/google/android/filament/EntityManager;->get()Lcom/google/android/filament/EntityManager;

    move-result-object v3

    invoke-direct {v2, p1, v1, v3}, Lcom/google/android/filament/gltfio/AssetLoader;-><init>(Lcom/google/android/filament/Engine;Lcom/google/android/filament/gltfio/MaterialProvider;Lcom/google/android/filament/EntityManager;)V

    iput-object v2, p0, Lcom/google/android/filament/utils/ModelViewer;->assetLoader:Lcom/google/android/filament/gltfio/AssetLoader;

    .line 20
    new-instance v1, Lcom/google/android/filament/gltfio/ResourceLoader;

    iget-boolean v2, p0, Lcom/google/android/filament/utils/ModelViewer;->normalizeSkinningWeights:Z

    invoke-direct {v1, p1, v2}, Lcom/google/android/filament/gltfio/ResourceLoader;-><init>(Lcom/google/android/filament/Engine;Z)V

    iput-object v1, p0, Lcom/google/android/filament/utils/ModelViewer;->resourceLoader:Lcom/google/android/filament/gltfio/ResourceLoader;

    .line 21
    invoke-static {}, Lcom/google/android/filament/EntityManager;->get()Lcom/google/android/filament/EntityManager;

    move-result-object v1

    invoke-virtual {v1}, Lcom/google/android/filament/EntityManager;->create()I

    move-result v1

    iput v1, p0, Lcom/google/android/filament/utils/ModelViewer;->light:I

    const p0, 0x45cb2000    # 6500.0f

    .line 22
    invoke-static {p0}, Lcom/google/android/filament/Colors;->cct(F)[F

    move-result-object p0

    const-string v2, "cct(...)"

    invoke-static {p0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v2, 0x0

    aget v2, p0, v2

    aget v3, p0, p2

    const/4 v4, 0x2

    aget p0, p0, v4

    .line 23
    new-instance v4, Lcom/google/android/filament/LightManager$Builder;

    sget-object v5, Lcom/google/android/filament/LightManager$Type;->DIRECTIONAL:Lcom/google/android/filament/LightManager$Type;

    invoke-direct {v4, v5}, Lcom/google/android/filament/LightManager$Builder;-><init>(Lcom/google/android/filament/LightManager$Type;)V

    .line 24
    invoke-virtual {v4, v2, v3, p0}, Lcom/google/android/filament/LightManager$Builder;->color(FFF)Lcom/google/android/filament/LightManager$Builder;

    move-result-object p0

    const v2, 0x47c35000    # 100000.0f

    .line 25
    invoke-virtual {p0, v2}, Lcom/google/android/filament/LightManager$Builder;->intensity(F)Lcom/google/android/filament/LightManager$Builder;

    move-result-object p0

    const/4 v2, 0x0

    const/high16 v3, -0x40800000    # -1.0f

    .line 26
    invoke-virtual {p0, v2, v3, v2}, Lcom/google/android/filament/LightManager$Builder;->direction(FFF)Lcom/google/android/filament/LightManager$Builder;

    move-result-object p0

    .line 27
    invoke-virtual {p0, p2}, Lcom/google/android/filament/LightManager$Builder;->castShadows(Z)Lcom/google/android/filament/LightManager$Builder;

    move-result-object p0

    .line 28
    invoke-virtual {p0, p1, v1}, Lcom/google/android/filament/LightManager$Builder;->build(Lcom/google/android/filament/Engine;I)V

    .line 29
    invoke-virtual {v0, v1}, Lcom/google/android/filament/Scene;->addEntity(I)V

    return-void
.end method

.method public static final synthetic access$fetchResources(Lcom/google/android/filament/utils/ModelViewer;Lcom/google/android/filament/gltfio/FilamentAsset;Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lcom/google/android/filament/utils/ModelViewer;->fetchResources(Lcom/google/android/filament/gltfio/FilamentAsset;Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static final synthetic access$getAssetLoader$p(Lcom/google/android/filament/utils/ModelViewer;)Lcom/google/android/filament/gltfio/AssetLoader;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/ModelViewer;->assetLoader:Lcom/google/android/filament/gltfio/AssetLoader;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$getCameraManipulator$p(Lcom/google/android/filament/utils/ModelViewer;)Lcom/google/android/filament/utils/Manipulator;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/ModelViewer;->cameraManipulator:Lcom/google/android/filament/utils/Manipulator;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$getDisplayHelper$p(Lcom/google/android/filament/utils/ModelViewer;)Lcom/google/android/filament/android/DisplayHelper;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/ModelViewer;->displayHelper:Lcom/google/android/filament/android/DisplayHelper;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$getMaterialProvider$p(Lcom/google/android/filament/utils/ModelViewer;)Lcom/google/android/filament/gltfio/MaterialProvider;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/ModelViewer;->materialProvider:Lcom/google/android/filament/gltfio/MaterialProvider;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$getResourceLoader$p(Lcom/google/android/filament/utils/ModelViewer;)Lcom/google/android/filament/gltfio/ResourceLoader;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/ModelViewer;->resourceLoader:Lcom/google/android/filament/gltfio/ResourceLoader;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$getSurfaceView$p(Lcom/google/android/filament/utils/ModelViewer;)Landroid/view/SurfaceView;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/ModelViewer;->surfaceView:Landroid/view/SurfaceView;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$getSwapChain$p(Lcom/google/android/filament/utils/ModelViewer;)Lcom/google/android/filament/SwapChain;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/ModelViewer;->swapChain:Lcom/google/android/filament/SwapChain;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$getTextureView$p(Lcom/google/android/filament/utils/ModelViewer;)Landroid/view/TextureView;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/ModelViewer;->textureView:Landroid/view/TextureView;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$getUiHelper$p(Lcom/google/android/filament/utils/ModelViewer;)Lcom/google/android/filament/android/UiHelper;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/ModelViewer;->uiHelper:Lcom/google/android/filament/android/UiHelper;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$setAnimator$p(Lcom/google/android/filament/utils/ModelViewer;Lcom/google/android/filament/gltfio/Animator;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/utils/ModelViewer;->animator:Lcom/google/android/filament/gltfio/Animator;

    .line 2
    .line 3
    return-void
.end method

.method public static final synthetic access$setSwapChain$p(Lcom/google/android/filament/utils/ModelViewer;Lcom/google/android/filament/SwapChain;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/utils/ModelViewer;->swapChain:Lcom/google/android/filament/SwapChain;

    .line 2
    .line 3
    return-void
.end method

.method public static final synthetic access$synchronizePendingFrames(Lcom/google/android/filament/utils/ModelViewer;Lcom/google/android/filament/Engine;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lcom/google/android/filament/utils/ModelViewer;->synchronizePendingFrames(Lcom/google/android/filament/Engine;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static final synthetic access$updateCameraProjection(Lcom/google/android/filament/utils/ModelViewer;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/google/android/filament/utils/ModelViewer;->updateCameraProjection()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private final addDetachListener(Landroid/view/View;)V
    .locals 1

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/ModelViewer$addDetachListener$1;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lcom/google/android/filament/utils/ModelViewer$addDetachListener$1;-><init>(Lcom/google/android/filament/utils/ModelViewer;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, v0}, Landroid/view/View;->addOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method private final fetchResources(Lcom/google/android/filament/gltfio/FilamentAsset;Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/google/android/filament/gltfio/FilamentAsset;",
            "Lay0/k;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/b0;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 1
    new-instance v0, Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Lcom/google/android/filament/gltfio/FilamentAsset;->getResourceUris()[Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    const-string v2, "getResourceUris(...)"

    .line 11
    .line 12
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    array-length v2, v1

    .line 16
    const/4 v3, 0x0

    .line 17
    :goto_0
    if-ge v3, v2, :cond_0

    .line 18
    .line 19
    aget-object v4, v1, v3

    .line 20
    .line 21
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    invoke-interface {p2, v4}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v5

    .line 28
    invoke-virtual {v0, v4, v5}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    add-int/lit8 v3, v3, 0x1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    sget-object p2, Lvy0/p0;->a:Lcz0/e;

    .line 35
    .line 36
    sget-object p2, Laz0/m;->a:Lwy0/c;

    .line 37
    .line 38
    new-instance v1, Lcom/google/android/filament/utils/ModelViewer$fetchResources$2;

    .line 39
    .line 40
    const/4 v2, 0x0

    .line 41
    invoke-direct {v1, v0, p0, p1, v2}, Lcom/google/android/filament/utils/ModelViewer$fetchResources$2;-><init>(Ljava/util/HashMap;Lcom/google/android/filament/utils/ModelViewer;Lcom/google/android/filament/gltfio/FilamentAsset;Lkotlin/coroutines/Continuation;)V

    .line 42
    .line 43
    .line 44
    invoke-static {p2, v1, p3}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 49
    .line 50
    if-ne p0, p1, :cond_1

    .line 51
    .line 52
    return-object p0

    .line 53
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 54
    .line 55
    return-object p0
.end method

.method public static synthetic getProgress$annotations()V
    .locals 0

    .line 1
    return-void
.end method

.method private final populateScene(Lcom/google/android/filament/gltfio/FilamentAsset;)V
    .locals 11

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer;->engine:Lcom/google/android/filament/Engine;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/android/filament/Engine;->getRenderableManager()Lcom/google/android/filament/RenderableManager;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-string v1, "getRenderableManager(...)"

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    new-instance v1, Lkotlin/jvm/internal/d0;

    .line 13
    .line 14
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 15
    .line 16
    .line 17
    :goto_0
    invoke-static {v1, p1, p0}, Lcom/google/android/filament/utils/ModelViewer;->populateScene$lambda$9(Lkotlin/jvm/internal/d0;Lcom/google/android/filament/gltfio/FilamentAsset;Lcom/google/android/filament/utils/ModelViewer;)Z

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    if-eqz v2, :cond_7

    .line 22
    .line 23
    iget v2, v1, Lkotlin/jvm/internal/d0;->d:I

    .line 24
    .line 25
    const/4 v3, 0x0

    .line 26
    move v4, v3

    .line 27
    :goto_1
    const/4 v5, 0x1

    .line 28
    if-ge v4, v2, :cond_0

    .line 29
    .line 30
    iget-object v6, p0, Lcom/google/android/filament/utils/ModelViewer;->readyRenderables:[I

    .line 31
    .line 32
    aget v6, v6, v4

    .line 33
    .line 34
    invoke-virtual {v0, v6}, Lcom/google/android/filament/RenderableManager;->getInstance(I)I

    .line 35
    .line 36
    .line 37
    move-result v6

    .line 38
    invoke-virtual {v0, v6, v5}, Lcom/google/android/filament/RenderableManager;->setScreenSpaceContactShadows(IZ)V

    .line 39
    .line 40
    .line 41
    add-int/lit8 v4, v4, 0x1

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_0
    iget-object v2, p0, Lcom/google/android/filament/utils/ModelViewer;->scene:Lcom/google/android/filament/Scene;

    .line 45
    .line 46
    iget-object v4, p0, Lcom/google/android/filament/utils/ModelViewer;->readyRenderables:[I

    .line 47
    .line 48
    iget v6, v1, Lkotlin/jvm/internal/d0;->d:I

    .line 49
    .line 50
    const-string v7, "<this>"

    .line 51
    .line 52
    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    if-ltz v6, :cond_6

    .line 56
    .line 57
    if-nez v6, :cond_1

    .line 58
    .line 59
    sget-object v3, Lmx0/s;->d:Lmx0/s;

    .line 60
    .line 61
    goto :goto_4

    .line 62
    :cond_1
    array-length v7, v4

    .line 63
    if-lt v6, v7, :cond_2

    .line 64
    .line 65
    invoke-static {v4}, Lmx0/n;->Z([I)Ljava/util/List;

    .line 66
    .line 67
    .line 68
    move-result-object v3

    .line 69
    goto :goto_4

    .line 70
    :cond_2
    if-ne v6, v5, :cond_3

    .line 71
    .line 72
    aget v3, v4, v3

    .line 73
    .line 74
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 75
    .line 76
    .line 77
    move-result-object v3

    .line 78
    invoke-static {v3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 79
    .line 80
    .line 81
    move-result-object v3

    .line 82
    goto :goto_4

    .line 83
    :cond_3
    new-instance v7, Ljava/util/ArrayList;

    .line 84
    .line 85
    invoke-direct {v7, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 86
    .line 87
    .line 88
    array-length v8, v4

    .line 89
    move v9, v3

    .line 90
    :goto_2
    if-ge v3, v8, :cond_5

    .line 91
    .line 92
    aget v10, v4, v3

    .line 93
    .line 94
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 95
    .line 96
    .line 97
    move-result-object v10

    .line 98
    invoke-virtual {v7, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 99
    .line 100
    .line 101
    add-int/2addr v9, v5

    .line 102
    if-ne v9, v6, :cond_4

    .line 103
    .line 104
    goto :goto_3

    .line 105
    :cond_4
    add-int/lit8 v3, v3, 0x1

    .line 106
    .line 107
    goto :goto_2

    .line 108
    :cond_5
    :goto_3
    move-object v3, v7

    .line 109
    :goto_4
    check-cast v3, Ljava/util/Collection;

    .line 110
    .line 111
    invoke-static {v3}, Lmx0/q;->w0(Ljava/util/Collection;)[I

    .line 112
    .line 113
    .line 114
    move-result-object v3

    .line 115
    invoke-virtual {v2, v3}, Lcom/google/android/filament/Scene;->addEntities([I)V

    .line 116
    .line 117
    .line 118
    goto :goto_0

    .line 119
    :cond_6
    const-string p0, "Requested element count "

    .line 120
    .line 121
    const-string p1, " is less than zero."

    .line 122
    .line 123
    invoke-static {p0, v6, p1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 128
    .line 129
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 130
    .line 131
    .line 132
    move-result-object p0

    .line 133
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    throw p1

    .line 137
    :cond_7
    iget-object p0, p0, Lcom/google/android/filament/utils/ModelViewer;->scene:Lcom/google/android/filament/Scene;

    .line 138
    .line 139
    invoke-virtual {p1}, Lcom/google/android/filament/gltfio/FilamentAsset;->getLightEntities()[I

    .line 140
    .line 141
    .line 142
    move-result-object p1

    .line 143
    invoke-virtual {p0, p1}, Lcom/google/android/filament/Scene;->addEntities([I)V

    .line 144
    .line 145
    .line 146
    return-void
.end method

.method private static final populateScene$lambda$9(Lkotlin/jvm/internal/d0;Lcom/google/android/filament/gltfio/FilamentAsset;Lcom/google/android/filament/utils/ModelViewer;)Z
    .locals 0

    .line 1
    iget-object p2, p2, Lcom/google/android/filament/utils/ModelViewer;->readyRenderables:[I

    .line 2
    .line 3
    invoke-virtual {p1, p2}, Lcom/google/android/filament/gltfio/FilamentAsset;->popRenderables([I)I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    iput p1, p0, Lkotlin/jvm/internal/d0;->d:I

    .line 8
    .line 9
    if-eqz p1, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method private final synchronizePendingFrames(Lcom/google/android/filament/Engine;)V
    .locals 3

    .line 1
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->createFence()Lcom/google/android/filament/Fence;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string v0, "createFence(...)"

    .line 6
    .line 7
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    sget-object v0, Lcom/google/android/filament/Fence$Mode;->FLUSH:Lcom/google/android/filament/Fence$Mode;

    .line 11
    .line 12
    const-wide/16 v1, -0x1

    .line 13
    .line 14
    invoke-virtual {p0, v0, v1, v2}, Lcom/google/android/filament/Fence;->wait(Lcom/google/android/filament/Fence$Mode;J)Lcom/google/android/filament/Fence$FenceStatus;

    .line 15
    .line 16
    .line 17
    invoke-virtual {p1, p0}, Lcom/google/android/filament/Engine;->destroyFence(Lcom/google/android/filament/Fence;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public static synthetic transformToUnitCube$default(Lcom/google/android/filament/utils/ModelViewer;Lcom/google/android/filament/utils/Float3;ILjava/lang/Object;)V
    .locals 0

    .line 1
    and-int/lit8 p2, p2, 0x1

    .line 2
    .line 3
    if-eqz p2, :cond_0

    .line 4
    .line 5
    sget-object p1, Lcom/google/android/filament/utils/ModelViewer;->kDefaultObjectPosition:Lcom/google/android/filament/utils/Float3;

    .line 6
    .line 7
    :cond_0
    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/ModelViewer;->transformToUnitCube(Lcom/google/android/filament/utils/Float3;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method private final updateCameraProjection()V
    .locals 13

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer;->view:Lcom/google/android/filament/View;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/android/filament/View;->getViewport()Lcom/google/android/filament/Viewport;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget v0, v0, Lcom/google/android/filament/Viewport;->width:I

    .line 8
    .line 9
    iget-object v1, p0, Lcom/google/android/filament/utils/ModelViewer;->view:Lcom/google/android/filament/View;

    .line 10
    .line 11
    invoke-virtual {v1}, Lcom/google/android/filament/View;->getViewport()Lcom/google/android/filament/Viewport;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    iget v1, v1, Lcom/google/android/filament/Viewport;->height:I

    .line 16
    .line 17
    int-to-double v2, v0

    .line 18
    int-to-double v0, v1

    .line 19
    div-double v7, v2, v0

    .line 20
    .line 21
    iget-object v4, p0, Lcom/google/android/filament/utils/ModelViewer;->camera:Lcom/google/android/filament/Camera;

    .line 22
    .line 23
    iget v0, p0, Lcom/google/android/filament/utils/ModelViewer;->cameraFocalLength:F

    .line 24
    .line 25
    float-to-double v5, v0

    .line 26
    iget v0, p0, Lcom/google/android/filament/utils/ModelViewer;->cameraNear:F

    .line 27
    .line 28
    float-to-double v9, v0

    .line 29
    iget p0, p0, Lcom/google/android/filament/utils/ModelViewer;->cameraFar:F

    .line 30
    .line 31
    float-to-double v11, p0

    .line 32
    invoke-virtual/range {v4 .. v12}, Lcom/google/android/filament/Camera;->setLensProjection(DDDD)V

    .line 33
    .line 34
    .line 35
    return-void
.end method


# virtual methods
.method public final clearRootTransform()V
    .locals 8

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer;->asset:Lcom/google/android/filament/gltfio/FilamentAsset;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lcom/google/android/filament/utils/ModelViewer;->engine:Lcom/google/android/filament/Engine;

    .line 6
    .line 7
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getTransformManager()Lcom/google/android/filament/TransformManager;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    const-string v1, "getTransformManager(...)"

    .line 12
    .line 13
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0}, Lcom/google/android/filament/gltfio/FilamentAsset;->getRoot()I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    invoke-virtual {p0, v0}, Lcom/google/android/filament/TransformManager;->getInstance(I)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    new-instance v1, Lcom/google/android/filament/utils/Mat4;

    .line 25
    .line 26
    const/16 v6, 0xf

    .line 27
    .line 28
    const/4 v7, 0x0

    .line 29
    const/4 v2, 0x0

    .line 30
    const/4 v3, 0x0

    .line 31
    const/4 v4, 0x0

    .line 32
    const/4 v5, 0x0

    .line 33
    invoke-direct/range {v1 .. v7}, Lcom/google/android/filament/utils/Mat4;-><init>(Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;Lcom/google/android/filament/utils/Float4;ILkotlin/jvm/internal/g;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Mat4;->toFloatArray()[F

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    invoke-virtual {p0, v0, v1}, Lcom/google/android/filament/TransformManager;->setTransform(I[F)V

    .line 41
    .line 42
    .line 43
    :cond_0
    return-void
.end method

.method public final destroyModel()V
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer;->fetchResourcesJob:Lvy0/i1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-interface {v0, v1}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 7
    .line 8
    .line 9
    :cond_0
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer;->resourceLoader:Lcom/google/android/filament/gltfio/ResourceLoader;

    .line 10
    .line 11
    invoke-virtual {v0}, Lcom/google/android/filament/gltfio/ResourceLoader;->asyncCancelLoad()V

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer;->resourceLoader:Lcom/google/android/filament/gltfio/ResourceLoader;

    .line 15
    .line 16
    invoke-virtual {v0}, Lcom/google/android/filament/gltfio/ResourceLoader;->evictResourceData()V

    .line 17
    .line 18
    .line 19
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer;->asset:Lcom/google/android/filament/gltfio/FilamentAsset;

    .line 20
    .line 21
    if-eqz v0, :cond_1

    .line 22
    .line 23
    iget-object v2, p0, Lcom/google/android/filament/utils/ModelViewer;->scene:Lcom/google/android/filament/Scene;

    .line 24
    .line 25
    invoke-virtual {v0}, Lcom/google/android/filament/gltfio/FilamentAsset;->getEntities()[I

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    invoke-virtual {v2, v3}, Lcom/google/android/filament/Scene;->removeEntities([I)V

    .line 30
    .line 31
    .line 32
    iget-object v2, p0, Lcom/google/android/filament/utils/ModelViewer;->assetLoader:Lcom/google/android/filament/gltfio/AssetLoader;

    .line 33
    .line 34
    invoke-virtual {v2, v0}, Lcom/google/android/filament/gltfio/AssetLoader;->destroyAsset(Lcom/google/android/filament/gltfio/FilamentAsset;)V

    .line 35
    .line 36
    .line 37
    iput-object v1, p0, Lcom/google/android/filament/utils/ModelViewer;->asset:Lcom/google/android/filament/gltfio/FilamentAsset;

    .line 38
    .line 39
    iput-object v1, p0, Lcom/google/android/filament/utils/ModelViewer;->animator:Lcom/google/android/filament/gltfio/Animator;

    .line 40
    .line 41
    :cond_1
    return-void
.end method

.method public final getAnimator()Lcom/google/android/filament/gltfio/Animator;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/ModelViewer;->animator:Lcom/google/android/filament/gltfio/Animator;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getAsset()Lcom/google/android/filament/gltfio/FilamentAsset;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/ModelViewer;->asset:Lcom/google/android/filament/gltfio/FilamentAsset;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getCamera()Lcom/google/android/filament/Camera;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/ModelViewer;->camera:Lcom/google/android/filament/Camera;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getCameraFar()F
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/filament/utils/ModelViewer;->cameraFar:F

    .line 2
    .line 3
    return p0
.end method

.method public final getCameraFocalLength()F
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/filament/utils/ModelViewer;->cameraFocalLength:F

    .line 2
    .line 3
    return p0
.end method

.method public final getCameraNear()F
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/filament/utils/ModelViewer;->cameraNear:F

    .line 2
    .line 3
    return p0
.end method

.method public final getEngine()Lcom/google/android/filament/Engine;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/ModelViewer;->engine:Lcom/google/android/filament/Engine;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getLight()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/filament/utils/ModelViewer;->light:I

    .line 2
    .line 3
    return p0
.end method

.method public final getNormalizeSkinningWeights()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/google/android/filament/utils/ModelViewer;->normalizeSkinningWeights:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getProgress()F
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/ModelViewer;->resourceLoader:Lcom/google/android/filament/gltfio/ResourceLoader;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/gltfio/ResourceLoader;->asyncGetLoadProgress()F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final getRenderer()Lcom/google/android/filament/Renderer;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/ModelViewer;->renderer:Lcom/google/android/filament/Renderer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getScene()Lcom/google/android/filament/Scene;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/ModelViewer;->scene:Lcom/google/android/filament/Scene;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getView()Lcom/google/android/filament/View;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/ModelViewer;->view:Lcom/google/android/filament/View;

    .line 2
    .line 3
    return-object p0
.end method

.method public final loadModelGlb(Ljava/nio/Buffer;)V
    .locals 1

    .line 1
    const-string v0, "buffer"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lcom/google/android/filament/utils/ModelViewer;->destroyModel()V

    .line 7
    .line 8
    .line 9
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer;->assetLoader:Lcom/google/android/filament/gltfio/AssetLoader;

    .line 10
    .line 11
    invoke-virtual {v0, p1}, Lcom/google/android/filament/gltfio/AssetLoader;->createAsset(Ljava/nio/Buffer;)Lcom/google/android/filament/gltfio/FilamentAsset;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    iput-object p1, p0, Lcom/google/android/filament/utils/ModelViewer;->asset:Lcom/google/android/filament/gltfio/FilamentAsset;

    .line 16
    .line 17
    if-eqz p1, :cond_0

    .line 18
    .line 19
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer;->resourceLoader:Lcom/google/android/filament/gltfio/ResourceLoader;

    .line 20
    .line 21
    invoke-virtual {v0, p1}, Lcom/google/android/filament/gltfio/ResourceLoader;->asyncBeginLoad(Lcom/google/android/filament/gltfio/FilamentAsset;)Z

    .line 22
    .line 23
    .line 24
    invoke-virtual {p1}, Lcom/google/android/filament/gltfio/FilamentAsset;->getInstance()Lcom/google/android/filament/gltfio/FilamentInstance;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-virtual {v0}, Lcom/google/android/filament/gltfio/FilamentInstance;->getAnimator()Lcom/google/android/filament/gltfio/Animator;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    iput-object v0, p0, Lcom/google/android/filament/utils/ModelViewer;->animator:Lcom/google/android/filament/gltfio/Animator;

    .line 33
    .line 34
    invoke-virtual {p1}, Lcom/google/android/filament/gltfio/FilamentAsset;->releaseSourceData()V

    .line 35
    .line 36
    .line 37
    :cond_0
    return-void
.end method

.method public final loadModelGltf(Ljava/nio/Buffer;Lay0/k;)V
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/nio/Buffer;",
            "Lay0/k;",
            ")V"
        }
    .end annotation

    .line 1
    const-string v0, "buffer"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "callback"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Lcom/google/android/filament/utils/ModelViewer;->destroyModel()V

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer;->assetLoader:Lcom/google/android/filament/gltfio/AssetLoader;

    .line 15
    .line 16
    invoke-virtual {v0, p1}, Lcom/google/android/filament/gltfio/AssetLoader;->createAsset(Ljava/nio/Buffer;)Lcom/google/android/filament/gltfio/FilamentAsset;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    iput-object p1, p0, Lcom/google/android/filament/utils/ModelViewer;->asset:Lcom/google/android/filament/gltfio/FilamentAsset;

    .line 21
    .line 22
    if-eqz p1, :cond_2

    .line 23
    .line 24
    invoke-virtual {p1}, Lcom/google/android/filament/gltfio/FilamentAsset;->getResourceUris()[Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    array-length v1, v0

    .line 29
    const/4 v2, 0x0

    .line 30
    :goto_0
    if-ge v2, v1, :cond_1

    .line 31
    .line 32
    aget-object v3, v0, v2

    .line 33
    .line 34
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    invoke-interface {p2, v3}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v4

    .line 41
    check-cast v4, Ljava/nio/Buffer;

    .line 42
    .line 43
    if-nez v4, :cond_0

    .line 44
    .line 45
    const/4 p1, 0x0

    .line 46
    iput-object p1, p0, Lcom/google/android/filament/utils/ModelViewer;->asset:Lcom/google/android/filament/gltfio/FilamentAsset;

    .line 47
    .line 48
    return-void

    .line 49
    :cond_0
    iget-object v5, p0, Lcom/google/android/filament/utils/ModelViewer;->resourceLoader:Lcom/google/android/filament/gltfio/ResourceLoader;

    .line 50
    .line 51
    invoke-virtual {v5, v3, v4}, Lcom/google/android/filament/gltfio/ResourceLoader;->addResourceData(Ljava/lang/String;Ljava/nio/Buffer;)Lcom/google/android/filament/gltfio/ResourceLoader;

    .line 52
    .line 53
    .line 54
    add-int/lit8 v2, v2, 0x1

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_1
    iget-object p2, p0, Lcom/google/android/filament/utils/ModelViewer;->resourceLoader:Lcom/google/android/filament/gltfio/ResourceLoader;

    .line 58
    .line 59
    invoke-virtual {p2, p1}, Lcom/google/android/filament/gltfio/ResourceLoader;->asyncBeginLoad(Lcom/google/android/filament/gltfio/FilamentAsset;)Z

    .line 60
    .line 61
    .line 62
    invoke-virtual {p1}, Lcom/google/android/filament/gltfio/FilamentAsset;->getInstance()Lcom/google/android/filament/gltfio/FilamentInstance;

    .line 63
    .line 64
    .line 65
    move-result-object p2

    .line 66
    invoke-virtual {p2}, Lcom/google/android/filament/gltfio/FilamentInstance;->getAnimator()Lcom/google/android/filament/gltfio/Animator;

    .line 67
    .line 68
    .line 69
    move-result-object p2

    .line 70
    iput-object p2, p0, Lcom/google/android/filament/utils/ModelViewer;->animator:Lcom/google/android/filament/gltfio/Animator;

    .line 71
    .line 72
    invoke-virtual {p1}, Lcom/google/android/filament/gltfio/FilamentAsset;->releaseSourceData()V

    .line 73
    .line 74
    .line 75
    :cond_2
    return-void
.end method

.method public final loadModelGltfAsync(Ljava/nio/Buffer;Lay0/k;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/nio/Buffer;",
            "Lay0/k;",
            ")V"
        }
    .end annotation

    .line 1
    const-string v0, "buffer"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "callback"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Lcom/google/android/filament/utils/ModelViewer;->destroyModel()V

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer;->assetLoader:Lcom/google/android/filament/gltfio/AssetLoader;

    .line 15
    .line 16
    invoke-virtual {v0, p1}, Lcom/google/android/filament/gltfio/AssetLoader;->createAsset(Ljava/nio/Buffer;)Lcom/google/android/filament/gltfio/FilamentAsset;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    iput-object p1, p0, Lcom/google/android/filament/utils/ModelViewer;->asset:Lcom/google/android/filament/gltfio/FilamentAsset;

    .line 21
    .line 22
    sget-object p1, Lvy0/p0;->a:Lcz0/e;

    .line 23
    .line 24
    sget-object p1, Lcz0/d;->e:Lcz0/d;

    .line 25
    .line 26
    invoke-static {p1}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    new-instance v0, Lcom/google/android/filament/utils/ModelViewer$loadModelGltfAsync$1;

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    invoke-direct {v0, p0, p2, v1}, Lcom/google/android/filament/utils/ModelViewer$loadModelGltfAsync$1;-><init>(Lcom/google/android/filament/utils/ModelViewer;Lay0/k;Lkotlin/coroutines/Continuation;)V

    .line 34
    .line 35
    .line 36
    const/4 p2, 0x3

    .line 37
    invoke-static {p1, v1, v1, v0, p2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    iput-object p1, p0, Lcom/google/android/filament/utils/ModelViewer;->fetchResourcesJob:Lvy0/i1;

    .line 42
    .line 43
    return-void
.end method

.method public onTouch(Landroid/view/View;Landroid/view/MotionEvent;)Z
    .locals 1

    .line 1
    const-string v0, "view"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p1, "event"

    .line 7
    .line 8
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0, p2}, Lcom/google/android/filament/utils/ModelViewer;->onTouchEvent(Landroid/view/MotionEvent;)V

    .line 12
    .line 13
    .line 14
    const/4 p0, 0x1

    .line 15
    return p0
.end method

.method public final onTouchEvent(Landroid/view/MotionEvent;)V
    .locals 1

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcom/google/android/filament/utils/ModelViewer;->gestureDetector:Lcom/google/android/filament/utils/GestureDetector;

    .line 7
    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/GestureDetector;->onTouchEvent(Landroid/view/MotionEvent;)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    const-string p0, "gestureDetector"

    .line 15
    .line 16
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    const/4 p0, 0x0

    .line 20
    throw p0
.end method

.method public final render(J)V
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lcom/google/android/filament/utils/ModelViewer;->uiHelper:Lcom/google/android/filament/android/UiHelper;

    .line 4
    .line 5
    invoke-virtual {v1}, Lcom/google/android/filament/android/UiHelper;->isReadyToRender()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    iget-object v1, v0, Lcom/google/android/filament/utils/ModelViewer;->resourceLoader:Lcom/google/android/filament/gltfio/ResourceLoader;

    .line 13
    .line 14
    invoke-virtual {v1}, Lcom/google/android/filament/gltfio/ResourceLoader;->asyncUpdateLoad()V

    .line 15
    .line 16
    .line 17
    iget-object v1, v0, Lcom/google/android/filament/utils/ModelViewer;->asset:Lcom/google/android/filament/gltfio/FilamentAsset;

    .line 18
    .line 19
    if-eqz v1, :cond_1

    .line 20
    .line 21
    invoke-direct {v0, v1}, Lcom/google/android/filament/utils/ModelViewer;->populateScene(Lcom/google/android/filament/gltfio/FilamentAsset;)V

    .line 22
    .line 23
    .line 24
    :cond_1
    iget-object v1, v0, Lcom/google/android/filament/utils/ModelViewer;->cameraManipulator:Lcom/google/android/filament/utils/Manipulator;

    .line 25
    .line 26
    if-eqz v1, :cond_3

    .line 27
    .line 28
    iget-object v2, v0, Lcom/google/android/filament/utils/ModelViewer;->eyePos:[D

    .line 29
    .line 30
    iget-object v3, v0, Lcom/google/android/filament/utils/ModelViewer;->target:[D

    .line 31
    .line 32
    iget-object v4, v0, Lcom/google/android/filament/utils/ModelViewer;->upward:[D

    .line 33
    .line 34
    invoke-virtual {v1, v2, v3, v4}, Lcom/google/android/filament/utils/Manipulator;->getLookAt([D[D[D)V

    .line 35
    .line 36
    .line 37
    iget-object v5, v0, Lcom/google/android/filament/utils/ModelViewer;->camera:Lcom/google/android/filament/Camera;

    .line 38
    .line 39
    iget-object v1, v0, Lcom/google/android/filament/utils/ModelViewer;->eyePos:[D

    .line 40
    .line 41
    const/4 v2, 0x0

    .line 42
    aget-wide v6, v1, v2

    .line 43
    .line 44
    const/4 v3, 0x1

    .line 45
    aget-wide v8, v1, v3

    .line 46
    .line 47
    const/4 v4, 0x2

    .line 48
    aget-wide v10, v1, v4

    .line 49
    .line 50
    iget-object v1, v0, Lcom/google/android/filament/utils/ModelViewer;->target:[D

    .line 51
    .line 52
    aget-wide v12, v1, v2

    .line 53
    .line 54
    aget-wide v14, v1, v3

    .line 55
    .line 56
    aget-wide v16, v1, v4

    .line 57
    .line 58
    iget-object v1, v0, Lcom/google/android/filament/utils/ModelViewer;->upward:[D

    .line 59
    .line 60
    aget-wide v18, v1, v2

    .line 61
    .line 62
    aget-wide v20, v1, v3

    .line 63
    .line 64
    aget-wide v22, v1, v4

    .line 65
    .line 66
    invoke-virtual/range {v5 .. v23}, Lcom/google/android/filament/Camera;->lookAt(DDDDDDDDD)V

    .line 67
    .line 68
    .line 69
    iget-object v1, v0, Lcom/google/android/filament/utils/ModelViewer;->renderer:Lcom/google/android/filament/Renderer;

    .line 70
    .line 71
    iget-object v2, v0, Lcom/google/android/filament/utils/ModelViewer;->swapChain:Lcom/google/android/filament/SwapChain;

    .line 72
    .line 73
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    move-wide/from16 v3, p1

    .line 77
    .line 78
    invoke-virtual {v1, v2, v3, v4}, Lcom/google/android/filament/Renderer;->beginFrame(Lcom/google/android/filament/SwapChain;J)Z

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    if-eqz v1, :cond_2

    .line 83
    .line 84
    iget-object v1, v0, Lcom/google/android/filament/utils/ModelViewer;->renderer:Lcom/google/android/filament/Renderer;

    .line 85
    .line 86
    iget-object v2, v0, Lcom/google/android/filament/utils/ModelViewer;->view:Lcom/google/android/filament/View;

    .line 87
    .line 88
    invoke-virtual {v1, v2}, Lcom/google/android/filament/Renderer;->render(Lcom/google/android/filament/View;)V

    .line 89
    .line 90
    .line 91
    iget-object v0, v0, Lcom/google/android/filament/utils/ModelViewer;->renderer:Lcom/google/android/filament/Renderer;

    .line 92
    .line 93
    invoke-virtual {v0}, Lcom/google/android/filament/Renderer;->endFrame()V

    .line 94
    .line 95
    .line 96
    :cond_2
    :goto_0
    return-void

    .line 97
    :cond_3
    const-string v0, "cameraManipulator"

    .line 98
    .line 99
    invoke-static {v0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    const/4 v0, 0x0

    .line 103
    throw v0
.end method

.method public final setCameraFar(F)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/google/android/filament/utils/ModelViewer;->cameraFar:F

    .line 2
    .line 3
    invoke-direct {p0}, Lcom/google/android/filament/utils/ModelViewer;->updateCameraProjection()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final setCameraFocalLength(F)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/google/android/filament/utils/ModelViewer;->cameraFocalLength:F

    .line 2
    .line 3
    invoke-direct {p0}, Lcom/google/android/filament/utils/ModelViewer;->updateCameraProjection()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final setCameraNear(F)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/google/android/filament/utils/ModelViewer;->cameraNear:F

    .line 2
    .line 3
    invoke-direct {p0}, Lcom/google/android/filament/utils/ModelViewer;->updateCameraProjection()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final setNormalizeSkinningWeights(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/google/android/filament/utils/ModelViewer;->normalizeSkinningWeights:Z

    .line 2
    .line 3
    return-void
.end method

.method public final transformToUnitCube(Lcom/google/android/filament/utils/Float3;)V
    .locals 8

    .line 1
    const-string v0, "centerPoint"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer;->asset:Lcom/google/android/filament/gltfio/FilamentAsset;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    iget-object p0, p0, Lcom/google/android/filament/utils/ModelViewer;->engine:Lcom/google/android/filament/Engine;

    .line 11
    .line 12
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getTransformManager()Lcom/google/android/filament/TransformManager;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    const-string v1, "getTransformManager(...)"

    .line 17
    .line 18
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0}, Lcom/google/android/filament/gltfio/FilamentAsset;->getBoundingBox()Lcom/google/android/filament/Box;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    invoke-virtual {v1}, Lcom/google/android/filament/Box;->getCenter()[F

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    new-instance v2, Lcom/google/android/filament/utils/Float3;

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    aget v4, v1, v3

    .line 33
    .line 34
    const/4 v5, 0x1

    .line 35
    aget v6, v1, v5

    .line 36
    .line 37
    const/4 v7, 0x2

    .line 38
    aget v1, v1, v7

    .line 39
    .line 40
    invoke-direct {v2, v4, v6, v1}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v0}, Lcom/google/android/filament/gltfio/FilamentAsset;->getBoundingBox()Lcom/google/android/filament/Box;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    invoke-virtual {v1}, Lcom/google/android/filament/Box;->getHalfExtent()[F

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    new-instance v4, Lcom/google/android/filament/utils/Float3;

    .line 52
    .line 53
    aget v3, v1, v3

    .line 54
    .line 55
    aget v5, v1, v5

    .line 56
    .line 57
    aget v1, v1, v7

    .line 58
    .line 59
    invoke-direct {v4, v3, v5, v1}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 63
    .line 64
    .line 65
    move-result v1

    .line 66
    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 67
    .line 68
    .line 69
    move-result v3

    .line 70
    invoke-virtual {v4}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 71
    .line 72
    .line 73
    move-result v4

    .line 74
    invoke-static {v3, v4}, Ljava/lang/Math;->max(FF)F

    .line 75
    .line 76
    .line 77
    move-result v3

    .line 78
    invoke-static {v1, v3}, Ljava/lang/Math;->max(FF)F

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    const/high16 v3, 0x40000000    # 2.0f

    .line 83
    .line 84
    mul-float/2addr v1, v3

    .line 85
    div-float/2addr v3, v1

    .line 86
    new-instance v1, Lcom/google/android/filament/utils/Float3;

    .line 87
    .line 88
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 89
    .line 90
    .line 91
    move-result v4

    .line 92
    div-float/2addr v4, v3

    .line 93
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 94
    .line 95
    .line 96
    move-result v5

    .line 97
    div-float/2addr v5, v3

    .line 98
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 99
    .line 100
    .line 101
    move-result p1

    .line 102
    div-float/2addr p1, v3

    .line 103
    invoke-direct {v1, v4, v5, p1}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 104
    .line 105
    .line 106
    new-instance p1, Lcom/google/android/filament/utils/Float3;

    .line 107
    .line 108
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 109
    .line 110
    .line 111
    move-result v4

    .line 112
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 113
    .line 114
    .line 115
    move-result v5

    .line 116
    sub-float/2addr v4, v5

    .line 117
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 118
    .line 119
    .line 120
    move-result v5

    .line 121
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 122
    .line 123
    .line 124
    move-result v6

    .line 125
    sub-float/2addr v5, v6

    .line 126
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 127
    .line 128
    .line 129
    move-result v2

    .line 130
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 131
    .line 132
    .line 133
    move-result v1

    .line 134
    sub-float/2addr v2, v1

    .line 135
    invoke-direct {p1, v4, v5, v2}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 136
    .line 137
    .line 138
    new-instance v1, Lcom/google/android/filament/utils/Float3;

    .line 139
    .line 140
    invoke-direct {v1, v3}, Lcom/google/android/filament/utils/Float3;-><init>(F)V

    .line 141
    .line 142
    .line 143
    invoke-static {v1}, Lcom/google/android/filament/utils/MatrixKt;->scale(Lcom/google/android/filament/utils/Float3;)Lcom/google/android/filament/utils/Mat4;

    .line 144
    .line 145
    .line 146
    move-result-object v1

    .line 147
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float3;->unaryMinus()Lcom/google/android/filament/utils/Float3;

    .line 148
    .line 149
    .line 150
    move-result-object p1

    .line 151
    invoke-static {p1}, Lcom/google/android/filament/utils/MatrixKt;->translation(Lcom/google/android/filament/utils/Float3;)Lcom/google/android/filament/utils/Mat4;

    .line 152
    .line 153
    .line 154
    move-result-object p1

    .line 155
    invoke-virtual {v1, p1}, Lcom/google/android/filament/utils/Mat4;->times(Lcom/google/android/filament/utils/Mat4;)Lcom/google/android/filament/utils/Mat4;

    .line 156
    .line 157
    .line 158
    move-result-object p1

    .line 159
    invoke-virtual {v0}, Lcom/google/android/filament/gltfio/FilamentAsset;->getRoot()I

    .line 160
    .line 161
    .line 162
    move-result v0

    .line 163
    invoke-virtual {p0, v0}, Lcom/google/android/filament/TransformManager;->getInstance(I)I

    .line 164
    .line 165
    .line 166
    move-result v0

    .line 167
    invoke-static {p1}, Lcom/google/android/filament/utils/MatrixKt;->transpose(Lcom/google/android/filament/utils/Mat4;)Lcom/google/android/filament/utils/Mat4;

    .line 168
    .line 169
    .line 170
    move-result-object p1

    .line 171
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Mat4;->toFloatArray()[F

    .line 172
    .line 173
    .line 174
    move-result-object p1

    .line 175
    invoke-virtual {p0, v0, p1}, Lcom/google/android/filament/TransformManager;->setTransform(I[F)V

    .line 176
    .line 177
    .line 178
    :cond_0
    return-void
.end method
