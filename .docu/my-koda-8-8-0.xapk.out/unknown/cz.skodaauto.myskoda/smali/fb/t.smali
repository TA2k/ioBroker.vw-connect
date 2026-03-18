.class public final synthetic Lfb/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lfb/u;


# direct methods
.method public synthetic constructor <init>(Lfb/u;I)V
    .locals 0

    .line 1
    iput p2, p0, Lfb/t;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lfb/t;->e:Lfb/u;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lfb/t;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    iget-object p0, p0, Lfb/t;->e:Lfb/u;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    iget-object v0, p0, Lfb/u;->c:Landroidx/work/impl/WorkDatabase;

    .line 11
    .line 12
    const-string v2, "getWorkDatabase(...)"

    .line 13
    .line 14
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    new-instance v2, La8/y0;

    .line 18
    .line 19
    const/16 v3, 0xc

    .line 20
    .line 21
    const-string v4, "widget_worker"

    .line 22
    .line 23
    invoke-direct {v2, v0, v4, p0, v3}, La8/y0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 24
    .line 25
    .line 26
    new-instance v3, Lh91/a;

    .line 27
    .line 28
    const/4 v4, 0x2

    .line 29
    invoke-direct {v3, v2, v4}, Lh91/a;-><init>(Ljava/lang/Runnable;I)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0, v3}, Lla/u;->p(Lay0/a;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    iget-object v2, p0, Lfb/u;->b:Leb/b;

    .line 36
    .line 37
    iget-object p0, p0, Lfb/u;->e:Ljava/util/List;

    .line 38
    .line 39
    invoke-static {v2, v0, p0}, Lfb/i;->b(Leb/b;Landroidx/work/impl/WorkDatabase;Ljava/util/List;)V

    .line 40
    .line 41
    .line 42
    return-object v1

    .line 43
    :pswitch_0
    iget-object v0, p0, Lfb/u;->c:Landroidx/work/impl/WorkDatabase;

    .line 44
    .line 45
    iget-object v2, p0, Lfb/u;->a:Landroid/content/Context;

    .line 46
    .line 47
    sget-object v3, Lhb/c;->i:Ljava/lang/String;

    .line 48
    .line 49
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 50
    .line 51
    const/16 v4, 0x22

    .line 52
    .line 53
    if-lt v3, v4, :cond_0

    .line 54
    .line 55
    invoke-static {v2}, Lhb/a;->b(Landroid/content/Context;)Landroid/app/job/JobScheduler;

    .line 56
    .line 57
    .line 58
    move-result-object v3

    .line 59
    invoke-virtual {v3}, Landroid/app/job/JobScheduler;->cancelAll()V

    .line 60
    .line 61
    .line 62
    :cond_0
    const-string v3, "jobscheduler"

    .line 63
    .line 64
    invoke-virtual {v2, v3}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v3

    .line 68
    check-cast v3, Landroid/app/job/JobScheduler;

    .line 69
    .line 70
    invoke-static {v2, v3}, Lhb/c;->d(Landroid/content/Context;Landroid/app/job/JobScheduler;)Ljava/util/ArrayList;

    .line 71
    .line 72
    .line 73
    move-result-object v2

    .line 74
    if-eqz v2, :cond_1

    .line 75
    .line 76
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 77
    .line 78
    .line 79
    move-result v4

    .line 80
    if-nez v4, :cond_1

    .line 81
    .line 82
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 83
    .line 84
    .line 85
    move-result-object v2

    .line 86
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 87
    .line 88
    .line 89
    move-result v4

    .line 90
    if-eqz v4, :cond_1

    .line 91
    .line 92
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v4

    .line 96
    check-cast v4, Landroid/app/job/JobInfo;

    .line 97
    .line 98
    invoke-virtual {v4}, Landroid/app/job/JobInfo;->getId()I

    .line 99
    .line 100
    .line 101
    move-result v4

    .line 102
    invoke-static {v3, v4}, Lhb/c;->b(Landroid/app/job/JobScheduler;I)V

    .line 103
    .line 104
    .line 105
    goto :goto_0

    .line 106
    :cond_1
    invoke-virtual {v0}, Landroidx/work/impl/WorkDatabase;->x()Lmb/s;

    .line 107
    .line 108
    .line 109
    move-result-object v2

    .line 110
    iget-object v2, v2, Lmb/s;->a:Lla/u;

    .line 111
    .line 112
    new-instance v3, Lm40/e;

    .line 113
    .line 114
    const/16 v4, 0x12

    .line 115
    .line 116
    invoke-direct {v3, v4}, Lm40/e;-><init>(I)V

    .line 117
    .line 118
    .line 119
    const/4 v4, 0x0

    .line 120
    const/4 v5, 0x1

    .line 121
    invoke-static {v2, v4, v5, v3}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v2

    .line 125
    check-cast v2, Ljava/lang/Number;

    .line 126
    .line 127
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 128
    .line 129
    .line 130
    iget-object v2, p0, Lfb/u;->b:Leb/b;

    .line 131
    .line 132
    iget-object p0, p0, Lfb/u;->e:Ljava/util/List;

    .line 133
    .line 134
    invoke-static {v2, v0, p0}, Lfb/i;->b(Leb/b;Landroidx/work/impl/WorkDatabase;Ljava/util/List;)V

    .line 135
    .line 136
    .line 137
    return-object v1

    .line 138
    nop

    .line 139
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
