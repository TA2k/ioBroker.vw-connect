.class public final synthetic Lg0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lc6/a;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lg0/c;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lg0/c;->b:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;)V
    .locals 4

    .line 1
    iget v0, p0, Lg0/c;->a:I

    .line 2
    .line 3
    iget-object p0, p0, Lg0/c;->b:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Ly4/h;

    .line 9
    .line 10
    check-cast p1, Lb0/i;

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Ly4/h;->b(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :pswitch_0
    check-cast p0, Lbb/i;

    .line 17
    .line 18
    check-cast p1, Lb0/i;

    .line 19
    .line 20
    const-string p1, "SurfaceViewImpl"

    .line 21
    .line 22
    const-string v0, "Safe to release surface."

    .line 23
    .line 24
    invoke-static {p1, v0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    if-eqz p0, :cond_0

    .line 28
    .line 29
    invoke-virtual {p0}, Lbb/i;->a()V

    .line 30
    .line 31
    .line 32
    :cond_0
    return-void

    .line 33
    :pswitch_1
    check-cast p0, Ljava/util/Map;

    .line 34
    .line 35
    check-cast p1, Lb0/j;

    .line 36
    .line 37
    invoke-interface {p0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    if-eqz v0, :cond_2

    .line 50
    .line 51
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    check-cast v0, Ljava/util/Map$Entry;

    .line 56
    .line 57
    iget v1, p1, Lb0/j;->b:I

    .line 58
    .line 59
    invoke-interface {v0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    check-cast v2, Lr0/b;

    .line 64
    .line 65
    iget v2, v2, Lr0/b;->f:I

    .line 66
    .line 67
    sub-int/2addr v1, v2

    .line 68
    invoke-interface {v0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v2

    .line 72
    check-cast v2, Lr0/b;

    .line 73
    .line 74
    iget-boolean v2, v2, Lr0/b;->g:Z

    .line 75
    .line 76
    if-eqz v2, :cond_1

    .line 77
    .line 78
    neg-int v1, v1

    .line 79
    :cond_1
    invoke-static {v1}, Li0/f;->i(I)I

    .line 80
    .line 81
    .line 82
    move-result v1

    .line 83
    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    check-cast v0, Lp0/k;

    .line 88
    .line 89
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 90
    .line 91
    .line 92
    new-instance v2, Lp0/i;

    .line 93
    .line 94
    const/4 v3, -0x1

    .line 95
    invoke-direct {v2, v0, v1, v3}, Lp0/i;-><init>(Lp0/k;II)V

    .line 96
    .line 97
    .line 98
    invoke-static {v2}, Llp/k1;->d(Ljava/lang/Runnable;)V

    .line 99
    .line 100
    .line 101
    goto :goto_0

    .line 102
    :cond_2
    return-void

    .line 103
    :pswitch_2
    check-cast p0, Lgw0/c;

    .line 104
    .line 105
    check-cast p1, Lg0/b;

    .line 106
    .line 107
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 108
    .line 109
    .line 110
    invoke-static {}, Llp/k1;->a()V

    .line 111
    .line 112
    .line 113
    return-void

    .line 114
    nop

    .line 115
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
