.class public final Lcom/google/ar/sceneform/rendering/c;
.super Lcom/google/ar/sceneform/rendering/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final e:Lcom/google/ar/sceneform/rendering/Texture;


# direct methods
.method public constructor <init>(Ljava/lang/String;Lcom/google/ar/sceneform/rendering/Texture;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/ar/sceneform/rendering/b;->d:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/google/ar/sceneform/rendering/c;->e:Lcom/google/ar/sceneform/rendering/Texture;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()Lcom/google/ar/sceneform/rendering/b;
    .locals 2

    .line 1
    new-instance v0, Lcom/google/ar/sceneform/rendering/c;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/ar/sceneform/rendering/b;->d:Ljava/lang/String;

    .line 4
    .line 5
    iget-object p0, p0, Lcom/google/ar/sceneform/rendering/c;->e:Lcom/google/ar/sceneform/rendering/Texture;

    .line 6
    .line 7
    invoke-direct {v0, v1, p0}, Lcom/google/ar/sceneform/rendering/c;-><init>(Ljava/lang/String;Lcom/google/ar/sceneform/rendering/Texture;)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method

.method public final bridge synthetic clone()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/ar/sceneform/rendering/c;->a()Lcom/google/ar/sceneform/rendering/b;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
