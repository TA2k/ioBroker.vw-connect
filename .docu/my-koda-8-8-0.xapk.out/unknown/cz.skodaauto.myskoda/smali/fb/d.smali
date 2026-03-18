.class public final synthetic Lfb/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/concurrent/Callable;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;

.field public final synthetic c:Ljava/lang/Object;

.field public final synthetic d:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p4, p0, Lfb/d;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lfb/d;->b:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Lfb/d;->c:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p3, p0, Lfb/d;->d:Ljava/lang/Object;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final call()Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lfb/d;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lfb/d;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lhs/f;

    .line 9
    .line 10
    iget-object v1, p0, Lfb/d;->c:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Ljava/util/concurrent/Callable;

    .line 13
    .line 14
    iget-object p0, p0, Lfb/d;->d:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, La0/j;

    .line 17
    .line 18
    iget-object v0, v0, Lhs/f;->d:Ljava/util/concurrent/ExecutorService;

    .line 19
    .line 20
    new-instance v2, Lh0/h0;

    .line 21
    .line 22
    const/4 v3, 0x7

    .line 23
    invoke-direct {v2, v3, v1, p0}, Lh0/h0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    invoke-interface {v0, v2}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0

    .line 31
    :pswitch_0
    iget-object v0, p0, Lfb/d;->b:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast v0, Lfb/e;

    .line 34
    .line 35
    iget-object v1, p0, Lfb/d;->c:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v1, Ljava/util/ArrayList;

    .line 38
    .line 39
    iget-object p0, p0, Lfb/d;->d:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast p0, Ljava/lang/String;

    .line 42
    .line 43
    iget-object v0, v0, Lfb/e;->e:Landroidx/work/impl/WorkDatabase;

    .line 44
    .line 45
    invoke-virtual {v0}, Landroidx/work/impl/WorkDatabase;->y()Lmb/u;

    .line 46
    .line 47
    .line 48
    move-result-object v2

    .line 49
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 50
    .line 51
    .line 52
    const-string v3, "id"

    .line 53
    .line 54
    invoke-static {p0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    iget-object v2, v2, Lmb/u;->a:Lla/u;

    .line 58
    .line 59
    new-instance v3, Lif0/d;

    .line 60
    .line 61
    const/16 v4, 0x1b

    .line 62
    .line 63
    invoke-direct {v3, p0, v4}, Lif0/d;-><init>(Ljava/lang/String;I)V

    .line 64
    .line 65
    .line 66
    const/4 v4, 0x1

    .line 67
    const/4 v5, 0x0

    .line 68
    invoke-static {v2, v4, v5, v3}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v2

    .line 72
    check-cast v2, Ljava/util/List;

    .line 73
    .line 74
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 75
    .line 76
    .line 77
    invoke-virtual {v0}, Landroidx/work/impl/WorkDatabase;->x()Lmb/s;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    invoke-virtual {v0, p0}, Lmb/s;->e(Ljava/lang/String;)Lmb/o;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    return-object p0

    .line 86
    nop

    .line 87
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
