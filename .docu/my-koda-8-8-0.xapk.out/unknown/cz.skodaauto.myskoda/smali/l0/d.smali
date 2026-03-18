.class public final synthetic Ll0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lc6/a;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;

.field public final synthetic c:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Ll0/d;->a:I

    .line 2
    .line 3
    iput-object p2, p0, Ll0/d;->b:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Ll0/d;->c:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;)V
    .locals 2

    .line 1
    iget v0, p0, Ll0/d;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ll0/d;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lq0/e;

    .line 9
    .line 10
    iget-object p0, p0, Ll0/d;->c:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Lp0/l;

    .line 13
    .line 14
    check-cast p1, Lb0/h;

    .line 15
    .line 16
    invoke-virtual {p0}, Lp0/l;->close()V

    .line 17
    .line 18
    .line 19
    iget-object p1, v0, Lq0/e;->k:Ljava/util/LinkedHashMap;

    .line 20
    .line 21
    invoke-interface {p1, p0}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Landroid/view/Surface;

    .line 26
    .line 27
    if-eqz p0, :cond_0

    .line 28
    .line 29
    iget-object p1, v0, Lq0/e;->d:Lq0/c;

    .line 30
    .line 31
    iget-object v0, p1, Lc1/k2;->f:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 34
    .line 35
    const/4 v1, 0x1

    .line 36
    invoke-static {v0, v1}, Lr0/i;->d(Ljava/util/concurrent/atomic/AtomicBoolean;Z)V

    .line 37
    .line 38
    .line 39
    iget-object v0, p1, Lc1/k2;->h:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v0, Ljava/lang/Thread;

    .line 42
    .line 43
    invoke-static {v0}, Lr0/i;->c(Ljava/lang/Thread;)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {p1, p0, v1}, Lc1/k2;->n(Landroid/view/Surface;Z)V

    .line 47
    .line 48
    .line 49
    :cond_0
    return-void

    .line 50
    :pswitch_0
    iget-object v0, p0, Ll0/d;->b:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v0, Lp0/c;

    .line 53
    .line 54
    iget-object p0, p0, Ll0/d;->c:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast p0, Lp0/l;

    .line 57
    .line 58
    check-cast p1, Lb0/h;

    .line 59
    .line 60
    invoke-virtual {p0}, Lp0/l;->close()V

    .line 61
    .line 62
    .line 63
    iget-object p1, v0, Lp0/c;->k:Ljava/util/LinkedHashMap;

    .line 64
    .line 65
    invoke-interface {p1, p0}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    check-cast p0, Landroid/view/Surface;

    .line 70
    .line 71
    if-eqz p0, :cond_1

    .line 72
    .line 73
    iget-object p1, v0, Lp0/c;->d:Lc1/k2;

    .line 74
    .line 75
    iget-object v0, p1, Lc1/k2;->f:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 78
    .line 79
    const/4 v1, 0x1

    .line 80
    invoke-static {v0, v1}, Lr0/i;->d(Ljava/util/concurrent/atomic/AtomicBoolean;Z)V

    .line 81
    .line 82
    .line 83
    iget-object v0, p1, Lc1/k2;->h:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast v0, Ljava/lang/Thread;

    .line 86
    .line 87
    invoke-static {v0}, Lr0/i;->c(Ljava/lang/Thread;)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {p1, p0, v1}, Lc1/k2;->n(Landroid/view/Surface;Z)V

    .line 91
    .line 92
    .line 93
    :cond_1
    return-void

    .line 94
    :pswitch_1
    iget-object v0, p0, Ll0/d;->b:Ljava/lang/Object;

    .line 95
    .line 96
    check-cast v0, Landroid/view/Surface;

    .line 97
    .line 98
    iget-object p0, p0, Ll0/d;->c:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast p0, Landroid/graphics/SurfaceTexture;

    .line 101
    .line 102
    check-cast p1, Lb0/i;

    .line 103
    .line 104
    invoke-virtual {v0}, Landroid/view/Surface;->release()V

    .line 105
    .line 106
    .line 107
    invoke-virtual {p0}, Landroid/graphics/SurfaceTexture;->release()V

    .line 108
    .line 109
    .line 110
    return-void

    .line 111
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
