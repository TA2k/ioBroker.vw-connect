.class Lcom/google/gson/internal/bind/TypeAdapters$28;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/gson/z;


# instance fields
.field public final synthetic d:Lcom/google/gson/reflect/TypeToken;

.field public final synthetic e:Lcom/google/gson/y;


# direct methods
.method public constructor <init>(Lcom/google/gson/reflect/TypeToken;Lcom/google/gson/y;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/gson/internal/bind/TypeAdapters$28;->d:Lcom/google/gson/reflect/TypeToken;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/google/gson/internal/bind/TypeAdapters$28;->e:Lcom/google/gson/y;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lcom/google/gson/j;Lcom/google/gson/reflect/TypeToken;)Lcom/google/gson/y;
    .locals 0

    .line 1
    iget-object p1, p0, Lcom/google/gson/internal/bind/TypeAdapters$28;->d:Lcom/google/gson/reflect/TypeToken;

    .line 2
    .line 3
    invoke-virtual {p2, p1}, Lcom/google/gson/reflect/TypeToken;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    if-eqz p1, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Lcom/google/gson/internal/bind/TypeAdapters$28;->e:Lcom/google/gson/y;

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return-object p0
.end method
