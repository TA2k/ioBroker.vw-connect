.class public final synthetic Leu0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Leu0/d;


# direct methods
.method public synthetic constructor <init>(Leu0/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Leu0/b;->a:Leu0/d;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lbq/a;)V
    .locals 10

    .line 1
    new-instance v0, Lmo/a;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Lmo/a;-><init>(Lmo/c;)V

    .line 4
    .line 5
    .line 6
    :goto_0
    invoke-virtual {v0}, Lmo/a;->hasNext()Z

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    if-eqz p1, :cond_1

    .line 11
    .line 12
    invoke-virtual {v0}, Lmo/a;->next()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    check-cast p1, Lcq/p;

    .line 17
    .line 18
    iget-object v1, p0, Leu0/b;->a:Leu0/d;

    .line 19
    .line 20
    iget-object v1, v1, Leu0/d;->b:Lau0/g;

    .line 21
    .line 22
    iget-object v2, p1, Lmo/b;->d:Lcom/google/android/gms/common/data/DataHolder;

    .line 23
    .line 24
    iget p1, p1, Lmo/b;->e:I

    .line 25
    .line 26
    invoke-static {v2}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    iget-object v3, v2, Lcom/google/android/gms/common/data/DataHolder;->g:[Landroid/database/CursorWindow;

    .line 30
    .line 31
    const/4 v4, 0x1

    .line 32
    const/4 v5, 0x0

    .line 33
    if-ltz p1, :cond_0

    .line 34
    .line 35
    iget v6, v2, Lcom/google/android/gms/common/data/DataHolder;->k:I

    .line 36
    .line 37
    if-ge p1, v6, :cond_0

    .line 38
    .line 39
    move v5, v4

    .line 40
    :cond_0
    invoke-static {v5}, Lno/c0;->k(Z)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v2, p1}, Lcom/google/android/gms/common/data/DataHolder;->x0(I)I

    .line 44
    .line 45
    .line 46
    move-result v5

    .line 47
    new-instance v6, Lau0/l;

    .line 48
    .line 49
    const-string v7, "path"

    .line 50
    .line 51
    invoke-virtual {v2, p1, v7}, Lcom/google/android/gms/common/data/DataHolder;->z0(ILjava/lang/String;)V

    .line 52
    .line 53
    .line 54
    aget-object v8, v3, v5

    .line 55
    .line 56
    iget-object v9, v2, Lcom/google/android/gms/common/data/DataHolder;->f:Landroid/os/Bundle;

    .line 57
    .line 58
    invoke-virtual {v9, v7}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 59
    .line 60
    .line 61
    move-result v7

    .line 62
    invoke-virtual {v8, p1, v7}, Landroid/database/CursorWindow;->getString(II)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v7

    .line 66
    invoke-static {v7}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 67
    .line 68
    .line 69
    move-result-object v7

    .line 70
    invoke-virtual {v7}, Landroid/net/Uri;->getPathSegments()Ljava/util/List;

    .line 71
    .line 72
    .line 73
    move-result-object v7

    .line 74
    invoke-interface {v7, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v4

    .line 78
    const-string v7, "get(...)"

    .line 79
    .line 80
    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    check-cast v4, Ljava/lang/String;

    .line 84
    .line 85
    const-string v7, "data"

    .line 86
    .line 87
    invoke-virtual {v2, p1, v7}, Lcom/google/android/gms/common/data/DataHolder;->z0(ILjava/lang/String;)V

    .line 88
    .line 89
    .line 90
    aget-object v3, v3, v5

    .line 91
    .line 92
    iget-object v2, v2, Lcom/google/android/gms/common/data/DataHolder;->f:Landroid/os/Bundle;

    .line 93
    .line 94
    invoke-virtual {v2, v7}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    invoke-virtual {v3, p1, v2}, Landroid/database/CursorWindow;->getBlob(II)[B

    .line 99
    .line 100
    .line 101
    move-result-object p1

    .line 102
    invoke-direct {v6, v4, p1}, Lau0/l;-><init>(Ljava/lang/String;[B)V

    .line 103
    .line 104
    .line 105
    iget-object p1, v1, Lau0/g;->c:Lyy0/i1;

    .line 106
    .line 107
    invoke-interface {p1, v6}, Lyy0/i1;->a(Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    goto :goto_0

    .line 111
    :cond_1
    return-void
.end method
