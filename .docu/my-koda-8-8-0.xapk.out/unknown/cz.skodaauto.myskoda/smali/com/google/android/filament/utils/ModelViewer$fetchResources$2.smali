.class final Lcom/google/android/filament/utils/ModelViewer$fetchResources$2;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/google/android/filament/utils/ModelViewer;->fetchResources(Lcom/google/android/filament/gltfio/FilamentAsset;Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lrx0/i;",
        "Lay0/n;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\n\u00a2\u0006\u0004\u0008\u0002\u0010\u0003"
    }
    d2 = {
        "Lvy0/b0;",
        "Llx0/b0;",
        "<anonymous>",
        "(Lvy0/b0;)V"
    }
    k = 0x3
    mv = {
        0x2,
        0x0,
        0x0
    }
.end annotation

.annotation runtime Lrx0/e;
    c = "com.google.android.filament.utils.ModelViewer$fetchResources$2"
    f = "ModelViewer.kt"
    l = {}
    m = "invokeSuspend"
.end annotation


# instance fields
.field final synthetic $asset:Lcom/google/android/filament/gltfio/FilamentAsset;

.field final synthetic $items:Ljava/util/HashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/HashMap<",
            "Ljava/lang/String;",
            "Ljava/nio/Buffer;",
            ">;"
        }
    .end annotation
.end field

.field label:I

.field final synthetic this$0:Lcom/google/android/filament/utils/ModelViewer;


# direct methods
.method public constructor <init>(Ljava/util/HashMap;Lcom/google/android/filament/utils/ModelViewer;Lcom/google/android/filament/gltfio/FilamentAsset;Lkotlin/coroutines/Continuation;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/HashMap<",
            "Ljava/lang/String;",
            "Ljava/nio/Buffer;",
            ">;",
            "Lcom/google/android/filament/utils/ModelViewer;",
            "Lcom/google/android/filament/gltfio/FilamentAsset;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lcom/google/android/filament/utils/ModelViewer$fetchResources$2;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/utils/ModelViewer$fetchResources$2;->$items:Ljava/util/HashMap;

    .line 2
    .line 3
    iput-object p2, p0, Lcom/google/android/filament/utils/ModelViewer$fetchResources$2;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 4
    .line 5
    iput-object p3, p0, Lcom/google/android/filament/utils/ModelViewer$fetchResources$2;->$asset:Lcom/google/android/filament/gltfio/FilamentAsset;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Object;",
            "Lkotlin/coroutines/Continuation<",
            "*>;)",
            "Lkotlin/coroutines/Continuation<",
            "Llx0/b0;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance p1, Lcom/google/android/filament/utils/ModelViewer$fetchResources$2;

    .line 2
    .line 3
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer$fetchResources$2;->$items:Ljava/util/HashMap;

    .line 4
    .line 5
    iget-object v1, p0, Lcom/google/android/filament/utils/ModelViewer$fetchResources$2;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 6
    .line 7
    iget-object p0, p0, Lcom/google/android/filament/utils/ModelViewer$fetchResources$2;->$asset:Lcom/google/android/filament/gltfio/FilamentAsset;

    .line 8
    .line 9
    invoke-direct {p1, v0, v1, p0, p2}, Lcom/google/android/filament/utils/ModelViewer$fetchResources$2;-><init>(Ljava/util/HashMap;Lcom/google/android/filament/utils/ModelViewer;Lcom/google/android/filament/gltfio/FilamentAsset;Lkotlin/coroutines/Continuation;)V

    .line 10
    .line 11
    .line 12
    return-object p1
.end method

.method public bridge synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    check-cast p2, Lkotlin/coroutines/Continuation;

    invoke-virtual {p0, p1, p2}, Lcom/google/android/filament/utils/ModelViewer$fetchResources$2;->invoke(Lvy0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invoke(Lvy0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lvy0/b0;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/b0;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 2
    invoke-virtual {p0, p1, p2}, Lcom/google/android/filament/utils/ModelViewer$fetchResources$2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    move-result-object p0

    check-cast p0, Lcom/google/android/filament/utils/ModelViewer$fetchResources$2;

    sget-object p1, Llx0/b0;->a:Llx0/b0;

    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/ModelViewer$fetchResources$2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v0, p0, Lcom/google/android/filament/utils/ModelViewer$fetchResources$2;->label:I

    .line 4
    .line 5
    if-nez v0, :cond_1

    .line 6
    .line 7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    iget-object p1, p0, Lcom/google/android/filament/utils/ModelViewer$fetchResources$2;->$items:Ljava/util/HashMap;

    .line 11
    .line 12
    invoke-interface {p1}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    check-cast v0, Ljava/util/Map$Entry;

    .line 31
    .line 32
    invoke-interface {v0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    check-cast v1, Ljava/lang/String;

    .line 37
    .line 38
    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    check-cast v0, Ljava/nio/Buffer;

    .line 43
    .line 44
    iget-object v2, p0, Lcom/google/android/filament/utils/ModelViewer$fetchResources$2;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 45
    .line 46
    invoke-static {v2}, Lcom/google/android/filament/utils/ModelViewer;->access$getResourceLoader$p(Lcom/google/android/filament/utils/ModelViewer;)Lcom/google/android/filament/gltfio/ResourceLoader;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    invoke-virtual {v2, v1, v0}, Lcom/google/android/filament/gltfio/ResourceLoader;->addResourceData(Ljava/lang/String;Ljava/nio/Buffer;)Lcom/google/android/filament/gltfio/ResourceLoader;

    .line 51
    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_0
    iget-object p1, p0, Lcom/google/android/filament/utils/ModelViewer$fetchResources$2;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 55
    .line 56
    invoke-static {p1}, Lcom/google/android/filament/utils/ModelViewer;->access$getResourceLoader$p(Lcom/google/android/filament/utils/ModelViewer;)Lcom/google/android/filament/gltfio/ResourceLoader;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer$fetchResources$2;->$asset:Lcom/google/android/filament/gltfio/FilamentAsset;

    .line 61
    .line 62
    invoke-virtual {p1, v0}, Lcom/google/android/filament/gltfio/ResourceLoader;->asyncBeginLoad(Lcom/google/android/filament/gltfio/FilamentAsset;)Z

    .line 63
    .line 64
    .line 65
    iget-object p1, p0, Lcom/google/android/filament/utils/ModelViewer$fetchResources$2;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 66
    .line 67
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer$fetchResources$2;->$asset:Lcom/google/android/filament/gltfio/FilamentAsset;

    .line 68
    .line 69
    invoke-virtual {v0}, Lcom/google/android/filament/gltfio/FilamentAsset;->getInstance()Lcom/google/android/filament/gltfio/FilamentInstance;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    invoke-virtual {v0}, Lcom/google/android/filament/gltfio/FilamentInstance;->getAnimator()Lcom/google/android/filament/gltfio/Animator;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    invoke-static {p1, v0}, Lcom/google/android/filament/utils/ModelViewer;->access$setAnimator$p(Lcom/google/android/filament/utils/ModelViewer;Lcom/google/android/filament/gltfio/Animator;)V

    .line 78
    .line 79
    .line 80
    iget-object p0, p0, Lcom/google/android/filament/utils/ModelViewer$fetchResources$2;->$asset:Lcom/google/android/filament/gltfio/FilamentAsset;

    .line 81
    .line 82
    invoke-virtual {p0}, Lcom/google/android/filament/gltfio/FilamentAsset;->releaseSourceData()V

    .line 83
    .line 84
    .line 85
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 86
    .line 87
    return-object p0

    .line 88
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 89
    .line 90
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 91
    .line 92
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    throw p0
.end method
