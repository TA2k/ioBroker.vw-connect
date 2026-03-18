.class final Lcom/google/gson/internal/bind/TreeTypeAdapter$SingleTypeFactory;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/gson/z;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/gson/internal/bind/TreeTypeAdapter;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "SingleTypeFactory"
.end annotation


# instance fields
.field public final d:Lcom/google/gson/reflect/TypeToken;

.field public final e:Z

.field public final f:Lcom/google/gson/s;

.field public final g:Lcom/google/gson/m;


# direct methods
.method public constructor <init>(Lcom/google/gson/m;Lcom/google/gson/reflect/TypeToken;Z)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    instance-of v0, p1, Lcom/google/gson/s;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    move-object v0, p1

    .line 9
    check-cast v0, Lcom/google/gson/s;

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 v0, 0x0

    .line 13
    :goto_0
    iput-object v0, p0, Lcom/google/gson/internal/bind/TreeTypeAdapter$SingleTypeFactory;->f:Lcom/google/gson/s;

    .line 14
    .line 15
    iput-object p1, p0, Lcom/google/gson/internal/bind/TreeTypeAdapter$SingleTypeFactory;->g:Lcom/google/gson/m;

    .line 16
    .line 17
    iput-object p2, p0, Lcom/google/gson/internal/bind/TreeTypeAdapter$SingleTypeFactory;->d:Lcom/google/gson/reflect/TypeToken;

    .line 18
    .line 19
    iput-boolean p3, p0, Lcom/google/gson/internal/bind/TreeTypeAdapter$SingleTypeFactory;->e:Z

    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final a(Lcom/google/gson/j;Lcom/google/gson/reflect/TypeToken;)Lcom/google/gson/y;
    .locals 10

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Lcom/google/gson/internal/bind/TreeTypeAdapter$SingleTypeFactory;->d:Lcom/google/gson/reflect/TypeToken;

    .line 3
    .line 4
    if-eqz v1, :cond_2

    .line 5
    .line 6
    invoke-virtual {v1, p2}, Lcom/google/gson/reflect/TypeToken;->equals(Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    move-result v2

    .line 10
    if-nez v2, :cond_1

    .line 11
    .line 12
    iget-boolean v2, p0, Lcom/google/gson/internal/bind/TreeTypeAdapter$SingleTypeFactory;->e:Z

    .line 13
    .line 14
    if-eqz v2, :cond_0

    .line 15
    .line 16
    invoke-virtual {v1}, Lcom/google/gson/reflect/TypeToken;->getType()Ljava/lang/reflect/Type;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    invoke-virtual {p2}, Lcom/google/gson/reflect/TypeToken;->getRawType()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    if-ne v1, v2, :cond_0

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    return-object v0

    .line 28
    :cond_1
    :goto_0
    new-instance v3, Lcom/google/gson/internal/bind/TreeTypeAdapter;

    .line 29
    .line 30
    iget-object v5, p0, Lcom/google/gson/internal/bind/TreeTypeAdapter$SingleTypeFactory;->g:Lcom/google/gson/m;

    .line 31
    .line 32
    const/4 v9, 0x1

    .line 33
    iget-object v4, p0, Lcom/google/gson/internal/bind/TreeTypeAdapter$SingleTypeFactory;->f:Lcom/google/gson/s;

    .line 34
    .line 35
    move-object v8, p0

    .line 36
    move-object v6, p1

    .line 37
    move-object v7, p2

    .line 38
    invoke-direct/range {v3 .. v9}, Lcom/google/gson/internal/bind/TreeTypeAdapter;-><init>(Lcom/google/gson/s;Lcom/google/gson/m;Lcom/google/gson/j;Lcom/google/gson/reflect/TypeToken;Lcom/google/gson/z;Z)V

    .line 39
    .line 40
    .line 41
    return-object v3

    .line 42
    :cond_2
    move-object v7, p2

    .line 43
    invoke-virtual {v7}, Lcom/google/gson/reflect/TypeToken;->getRawType()Ljava/lang/Class;

    .line 44
    .line 45
    .line 46
    throw v0
.end method
