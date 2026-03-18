.class Lcom/google/gson/internal/bind/ObjectTypeAdapter$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/gson/z;


# instance fields
.field public final synthetic d:Lcom/google/gson/x;


# direct methods
.method public constructor <init>(Lcom/google/gson/x;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/gson/internal/bind/ObjectTypeAdapter$1;->d:Lcom/google/gson/x;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lcom/google/gson/j;Lcom/google/gson/reflect/TypeToken;)Lcom/google/gson/y;
    .locals 1

    .line 1
    invoke-virtual {p2}, Lcom/google/gson/reflect/TypeToken;->getRawType()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    const-class v0, Ljava/lang/Object;

    .line 6
    .line 7
    if-ne p2, v0, :cond_0

    .line 8
    .line 9
    new-instance p2, Lcom/google/gson/internal/bind/ObjectTypeAdapter;

    .line 10
    .line 11
    iget-object p0, p0, Lcom/google/gson/internal/bind/ObjectTypeAdapter$1;->d:Lcom/google/gson/x;

    .line 12
    .line 13
    invoke-direct {p2, p1, p0}, Lcom/google/gson/internal/bind/ObjectTypeAdapter;-><init>(Lcom/google/gson/j;Lcom/google/gson/x;)V

    .line 14
    .line 15
    .line 16
    return-object p2

    .line 17
    :cond_0
    const/4 p0, 0x0

    .line 18
    return-object p0
.end method
