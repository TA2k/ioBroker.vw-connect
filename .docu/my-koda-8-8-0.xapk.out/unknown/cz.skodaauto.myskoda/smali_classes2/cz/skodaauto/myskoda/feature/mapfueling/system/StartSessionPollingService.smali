.class public final Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;
.super Landroid/app/Service;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ly11/a;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0003\u0008\u0001\u0018\u00002\u00020\u00012\u00020\u00022\u00020\u0003B\u0007\u00a2\u0006\u0004\u0008\u0004\u0010\u0005\u00a8\u0006\u0006"
    }
    d2 = {
        "Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;",
        "Landroid/app/Service;",
        "Ly11/a;",
        "",
        "<init>",
        "()V",
        "map-fueling_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final n:J

.field public static final o:J

.field public static final synthetic p:I


# instance fields
.field public final d:Ljava/lang/Object;

.field public final e:Ljava/lang/Object;

.field public final f:Ljava/lang/Object;

.field public final g:Ljava/lang/Object;

.field public final h:Ljava/lang/Object;

.field public final i:Ljava/lang/Object;

.field public j:Lvy0/x1;

.field public k:Lvy0/x1;

.field public l:Z

.field public m:Landroidx/core/app/x;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget v0, Lmy0/c;->g:I

    .line 2
    .line 3
    const/16 v0, 0x8

    .line 4
    .line 5
    sget-object v1, Lmy0/e;->i:Lmy0/e;

    .line 6
    .line 7
    invoke-static {v0, v1}, Lmy0/h;->s(ILmy0/e;)J

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    sput-wide v0, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->n:J

    .line 12
    .line 13
    const/4 v0, 0x1

    .line 14
    sget-object v1, Lmy0/e;->h:Lmy0/e;

    .line 15
    .line 16
    invoke-static {v0, v1}, Lmy0/h;->s(ILmy0/e;)J

    .line 17
    .line 18
    .line 19
    move-result-wide v0

    .line 20
    sput-wide v0, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->o:J

    .line 21
    .line 22
    return-void
.end method

.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Landroid/app/Service;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Llx0/j;->d:Llx0/j;

    .line 5
    .line 6
    new-instance v1, Lbp0/h;

    .line 7
    .line 8
    const/16 v2, 0x9

    .line 9
    .line 10
    invoke-direct {v1, p0, v2}, Lbp0/h;-><init>(Ly11/a;I)V

    .line 11
    .line 12
    .line 13
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    iput-object v1, p0, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->d:Ljava/lang/Object;

    .line 18
    .line 19
    new-instance v1, Lbp0/h;

    .line 20
    .line 21
    const/16 v2, 0xa

    .line 22
    .line 23
    invoke-direct {v1, p0, v2}, Lbp0/h;-><init>(Ly11/a;I)V

    .line 24
    .line 25
    .line 26
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    iput-object v1, p0, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->e:Ljava/lang/Object;

    .line 31
    .line 32
    new-instance v1, Lbp0/h;

    .line 33
    .line 34
    const/16 v2, 0xb

    .line 35
    .line 36
    invoke-direct {v1, p0, v2}, Lbp0/h;-><init>(Ly11/a;I)V

    .line 37
    .line 38
    .line 39
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    iput-object v1, p0, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->f:Ljava/lang/Object;

    .line 44
    .line 45
    new-instance v1, Lbp0/h;

    .line 46
    .line 47
    const/16 v2, 0xc

    .line 48
    .line 49
    invoke-direct {v1, p0, v2}, Lbp0/h;-><init>(Ly11/a;I)V

    .line 50
    .line 51
    .line 52
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    iput-object v1, p0, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->g:Ljava/lang/Object;

    .line 57
    .line 58
    new-instance v1, Lbp0/h;

    .line 59
    .line 60
    const/16 v2, 0xd

    .line 61
    .line 62
    invoke-direct {v1, p0, v2}, Lbp0/h;-><init>(Ly11/a;I)V

    .line 63
    .line 64
    .line 65
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    iput-object v1, p0, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->h:Ljava/lang/Object;

    .line 70
    .line 71
    new-instance v1, Lbp0/h;

    .line 72
    .line 73
    const/16 v2, 0xe

    .line 74
    .line 75
    invoke-direct {v1, p0, v2}, Lbp0/h;-><init>(Ly11/a;I)V

    .line 76
    .line 77
    .line 78
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    iput-object v0, p0, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->i:Ljava/lang/Object;

    .line 83
    .line 84
    const/4 v0, 0x1

    .line 85
    iput-boolean v0, p0, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->l:Z

    .line 86
    .line 87
    return-void
.end method

.method public static final a(Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Lr40/i;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lr40/i;

    .line 7
    .line 8
    iget v1, v0, Lr40/i;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lr40/i;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lr40/i;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lr40/i;-><init>(Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lr40/i;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lr40/i;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    iget-object p1, p0, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->h:Ljava/lang/Object;

    .line 52
    .line 53
    invoke-interface {p1}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    check-cast p1, Lo40/d0;

    .line 58
    .line 59
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    iget-object p1, p0, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->f:Ljava/lang/Object;

    .line 63
    .line 64
    invoke-interface {p1}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    check-cast p1, Lo40/y;

    .line 69
    .line 70
    sget-object v2, Lon0/h;->g:Lon0/h;

    .line 71
    .line 72
    invoke-virtual {p1, v2}, Lo40/y;->a(Lon0/h;)V

    .line 73
    .line 74
    .line 75
    const p1, 0x7f1202be

    .line 76
    .line 77
    .line 78
    invoke-virtual {p0, p1}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    const-string v2, "getString(...)"

    .line 83
    .line 84
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    const v2, 0x7f1202bc

    .line 88
    .line 89
    .line 90
    invoke-virtual {p0, v2}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v2

    .line 94
    iput v3, v0, Lr40/i;->f:I

    .line 95
    .line 96
    const-string v3, "myskoda://app/maps/pay-to-fuel/summary-error"

    .line 97
    .line 98
    invoke-virtual {p0, p1, v2, v3, v0}, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object p1

    .line 102
    if-ne p1, v1, :cond_3

    .line 103
    .line 104
    return-object v1

    .line 105
    :cond_3
    :goto_1
    iget-object p0, p0, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->k:Lvy0/x1;

    .line 106
    .line 107
    if-eqz p0, :cond_4

    .line 108
    .line 109
    const/4 p1, 0x0

    .line 110
    invoke-virtual {p0, p1}, Lvy0/p1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 111
    .line 112
    .line 113
    :cond_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 114
    .line 115
    return-object p0
.end method

.method public static final c(Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;Lon0/h;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p2, Lr40/j;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lr40/j;

    .line 7
    .line 8
    iget v1, v0, Lr40/j;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lr40/j;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lr40/j;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lr40/j;-><init>(Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lr40/j;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lr40/j;->f:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    const/4 v5, 0x0

    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    if-eq v2, v4, :cond_1

    .line 37
    .line 38
    if-ne v2, v3, :cond_2

    .line 39
    .line 40
    :cond_1
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    goto :goto_2

    .line 44
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    iget-object p2, p0, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->f:Ljava/lang/Object;

    .line 56
    .line 57
    invoke-interface {p2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p2

    .line 61
    check-cast p2, Lo40/y;

    .line 62
    .line 63
    invoke-virtual {p2, p1}, Lo40/y;->a(Lon0/h;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 67
    .line 68
    .line 69
    move-result p1

    .line 70
    const/4 p2, 0x5

    .line 71
    const-string v2, "getString(...)"

    .line 72
    .line 73
    if-eq p1, p2, :cond_5

    .line 74
    .line 75
    const/16 p2, 0xd

    .line 76
    .line 77
    if-eq p1, p2, :cond_4

    .line 78
    .line 79
    const/4 p2, 0x7

    .line 80
    if-eq p1, p2, :cond_5

    .line 81
    .line 82
    const/16 p2, 0x8

    .line 83
    .line 84
    if-eq p1, p2, :cond_5

    .line 85
    .line 86
    goto :goto_2

    .line 87
    :cond_4
    const p1, 0x7f120e44

    .line 88
    .line 89
    .line 90
    invoke-virtual {p0, p1}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object p1

    .line 94
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    iput v3, v0, Lr40/j;->f:I

    .line 98
    .line 99
    const-string p2, "myskoda://app/maps/pay-to-fuel/summary"

    .line 100
    .line 101
    invoke-virtual {p0, p1, v5, p2, v0}, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object p1

    .line 105
    if-ne p1, v1, :cond_6

    .line 106
    .line 107
    goto :goto_1

    .line 108
    :cond_5
    const p1, 0x7f120e40

    .line 109
    .line 110
    .line 111
    invoke-virtual {p0, p1}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object p1

    .line 115
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    const p2, 0x7f120e41

    .line 119
    .line 120
    .line 121
    invoke-virtual {p0, p2}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 122
    .line 123
    .line 124
    move-result-object p2

    .line 125
    iput v4, v0, Lr40/j;->f:I

    .line 126
    .line 127
    const-string v2, "myskoda://app/maps/pay-to-fuel/summary-error"

    .line 128
    .line 129
    invoke-virtual {p0, p1, p2, v2, v0}, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object p1

    .line 133
    if-ne p1, v1, :cond_6

    .line 134
    .line 135
    :goto_1
    return-object v1

    .line 136
    :cond_6
    :goto_2
    iget-object p0, p0, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->k:Lvy0/x1;

    .line 137
    .line 138
    if-eqz p0, :cond_7

    .line 139
    .line 140
    invoke-virtual {p0, v5}, Lvy0/p1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 141
    .line 142
    .line 143
    :cond_7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 144
    .line 145
    return-object p0
.end method


# virtual methods
.method public final bridge b()Landroidx/lifecycle/c1;
    .locals 0

    .line 1
    invoke-static {}, Llp/qf;->a()Landroidx/lifecycle/c1;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p4, Lr40/h;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p4

    .line 6
    check-cast v0, Lr40/h;

    .line 7
    .line 8
    iget v1, v0, Lr40/h;->i:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lr40/h;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lr40/h;

    .line 21
    .line 22
    invoke-direct {v0, p0, p4}, Lr40/h;-><init>(Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p4, v0, Lr40/h;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lr40/h;->i:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    if-ne v2, v4, :cond_1

    .line 36
    .line 37
    iget-object p3, v0, Lr40/h;->f:Ljava/lang/String;

    .line 38
    .line 39
    iget-object p2, v0, Lr40/h;->e:Ljava/lang/String;

    .line 40
    .line 41
    iget-object p1, v0, Lr40/h;->d:Ljava/lang/String;

    .line 42
    .line 43
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_2
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    iput-boolean v3, p0, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->l:Z

    .line 59
    .line 60
    sget-wide v5, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->o:J

    .line 61
    .line 62
    invoke-static {v5, v6}, Lmy0/c;->e(J)J

    .line 63
    .line 64
    .line 65
    move-result-wide v5

    .line 66
    iput-object p1, v0, Lr40/h;->d:Ljava/lang/String;

    .line 67
    .line 68
    iput-object p2, v0, Lr40/h;->e:Ljava/lang/String;

    .line 69
    .line 70
    iput-object p3, v0, Lr40/h;->f:Ljava/lang/String;

    .line 71
    .line 72
    iput v4, v0, Lr40/h;->i:I

    .line 73
    .line 74
    invoke-static {v5, v6, v0}, Lvy0/e0;->p(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object p4

    .line 78
    if-ne p4, v1, :cond_3

    .line 79
    .line 80
    return-object v1

    .line 81
    :cond_3
    :goto_1
    iget-object p4, p0, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->m:Landroidx/core/app/x;

    .line 82
    .line 83
    if-eqz p4, :cond_5

    .line 84
    .line 85
    invoke-static {p1}, Landroidx/core/app/x;->b(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 86
    .line 87
    .line 88
    move-result-object p1

    .line 89
    iput-object p1, p4, Landroidx/core/app/x;->e:Ljava/lang/CharSequence;

    .line 90
    .line 91
    const p1, 0x7f0805dd

    .line 92
    .line 93
    .line 94
    iget-object v0, p4, Landroidx/core/app/x;->y:Landroid/app/Notification;

    .line 95
    .line 96
    iput p1, v0, Landroid/app/Notification;->icon:I

    .line 97
    .line 98
    new-instance p1, Landroid/content/Intent;

    .line 99
    .line 100
    invoke-direct {p1}, Landroid/content/Intent;-><init>()V

    .line 101
    .line 102
    .line 103
    const-string v0, "android.intent.action.VIEW"

    .line 104
    .line 105
    invoke-virtual {p1, v0}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    .line 106
    .line 107
    .line 108
    invoke-static {p3}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 109
    .line 110
    .line 111
    move-result-object p3

    .line 112
    invoke-virtual {p1, p3}, Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;

    .line 113
    .line 114
    .line 115
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object p3

    .line 119
    invoke-virtual {p1, p3}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;

    .line 120
    .line 121
    .line 122
    const/high16 p3, 0x4000000

    .line 123
    .line 124
    invoke-static {p0, v3, p1, p3}, Landroid/app/PendingIntent;->getActivity(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;

    .line 125
    .line 126
    .line 127
    move-result-object p1

    .line 128
    iput-object p1, p4, Landroidx/core/app/x;->g:Landroid/app/PendingIntent;

    .line 129
    .line 130
    if-eqz p2, :cond_4

    .line 131
    .line 132
    invoke-virtual {p4, p2}, Landroidx/core/app/x;->c(Ljava/lang/CharSequence;)V

    .line 133
    .line 134
    .line 135
    goto :goto_2

    .line 136
    :cond_4
    const-string p1, ""

    .line 137
    .line 138
    invoke-virtual {p4, p1}, Landroidx/core/app/x;->c(Ljava/lang/CharSequence;)V

    .line 139
    .line 140
    .line 141
    :goto_2
    iget-object p0, p0, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->g:Ljava/lang/Object;

    .line 142
    .line 143
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    check-cast p0, Landroid/app/NotificationManager;

    .line 148
    .line 149
    invoke-virtual {p4}, Landroidx/core/app/x;->a()Landroid/app/Notification;

    .line 150
    .line 151
    .line 152
    move-result-object p1

    .line 153
    invoke-virtual {p0, v4, p1}, Landroid/app/NotificationManager;->notify(ILandroid/app/Notification;)V

    .line 154
    .line 155
    .line 156
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 157
    .line 158
    return-object p0

    .line 159
    :cond_5
    const-string p0, "curNotification"

    .line 160
    .line 161
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    const/4 p0, 0x0

    .line 165
    throw p0
.end method

.method public final onBind(Landroid/content/Intent;)Landroid/os/IBinder;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public final onCreate()V
    .locals 4

    .line 1
    invoke-super {p0}, Landroid/app/Service;->onCreate()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Landroidx/core/app/x;

    .line 5
    .line 6
    const-string v1, "ongoing_tasks_channel"

    .line 7
    .line 8
    invoke-direct {v0, p0, v1}, Landroidx/core/app/x;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const v1, 0x7f08047b

    .line 12
    .line 13
    .line 14
    iget-object v2, v0, Landroidx/core/app/x;->y:Landroid/app/Notification;

    .line 15
    .line 16
    iput v1, v2, Landroid/app/Notification;->icon:I

    .line 17
    .line 18
    const v1, 0x7f120e43

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0, v1}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    invoke-static {v1}, Landroidx/core/app/x;->b(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    iput-object v1, v0, Landroidx/core/app/x;->e:Ljava/lang/CharSequence;

    .line 30
    .line 31
    new-instance v1, Landroid/content/Intent;

    .line 32
    .line 33
    invoke-direct {v1}, Landroid/content/Intent;-><init>()V

    .line 34
    .line 35
    .line 36
    const-string v2, "android.intent.action.VIEW"

    .line 37
    .line 38
    invoke-virtual {v1, v2}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    .line 39
    .line 40
    .line 41
    const-string v2, "myskoda://app/maps/pay-to-fuel/disclaimer"

    .line 42
    .line 43
    invoke-static {v2}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    invoke-virtual {v1, v2}, Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;

    .line 48
    .line 49
    .line 50
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v2

    .line 54
    invoke-virtual {v1, v2}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;

    .line 55
    .line 56
    .line 57
    const/high16 v2, 0x4000000

    .line 58
    .line 59
    const/4 v3, 0x0

    .line 60
    invoke-static {p0, v3, v1, v2}, Landroid/app/PendingIntent;->getActivity(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    iput-object v1, v0, Landroidx/core/app/x;->g:Landroid/app/PendingIntent;

    .line 65
    .line 66
    iput-object v0, p0, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->m:Landroidx/core/app/x;

    .line 67
    .line 68
    return-void
.end method

.method public final onStartCommand(Landroid/content/Intent;II)I
    .locals 11

    .line 1
    const/4 v4, 0x0

    .line 2
    if-eqz p1, :cond_0

    .line 3
    .line 4
    invoke-virtual {p1}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move-object v0, v4

    .line 10
    :goto_0
    sget-object v2, Lyh0/a;->d:[Lyh0/a;

    .line 11
    .line 12
    const-string v2, "Start"

    .line 13
    .line 14
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    if-eqz v2, :cond_4

    .line 19
    .line 20
    iget-object v0, p0, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->j:Lvy0/x1;

    .line 21
    .line 22
    const/4 v6, 0x1

    .line 23
    if-eqz v0, :cond_1

    .line 24
    .line 25
    invoke-virtual {v0}, Lvy0/p1;->a()Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-ne v0, v6, :cond_1

    .line 30
    .line 31
    goto :goto_1

    .line 32
    :cond_1
    sget-wide v7, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->n:J

    .line 33
    .line 34
    invoke-static {v7, v8}, Lmy0/c;->e(J)J

    .line 35
    .line 36
    .line 37
    move-result-wide v2

    .line 38
    sget-object v9, Lge0/b;->c:Lcz0/d;

    .line 39
    .line 40
    invoke-static {v9}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 41
    .line 42
    .line 43
    move-result-object v10

    .line 44
    new-instance v0, Le2/f0;

    .line 45
    .line 46
    const/4 v5, 0x5

    .line 47
    move-object v1, p0

    .line 48
    invoke-direct/range {v0 .. v5}, Le2/f0;-><init>(Ljava/lang/Object;JLkotlin/coroutines/Continuation;I)V

    .line 49
    .line 50
    .line 51
    const/4 v2, 0x3

    .line 52
    invoke-static {v10, v4, v4, v0, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 53
    .line 54
    .line 55
    iget-object v0, p0, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->m:Landroidx/core/app/x;

    .line 56
    .line 57
    if-eqz v0, :cond_3

    .line 58
    .line 59
    invoke-virtual {v0}, Landroidx/core/app/x;->a()Landroid/app/Notification;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    invoke-virtual {p0, v6, v0, v6}, Landroid/app/Service;->startForeground(ILandroid/app/Notification;I)V

    .line 64
    .line 65
    .line 66
    iget-object v0, p0, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->j:Lvy0/x1;

    .line 67
    .line 68
    if-eqz v0, :cond_2

    .line 69
    .line 70
    invoke-virtual {v0, v4}, Lvy0/p1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 71
    .line 72
    .line 73
    :cond_2
    invoke-static {v9}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    new-instance v3, Lr40/k;

    .line 78
    .line 79
    invoke-direct {v3, v7, v8, p0, v4}, Lr40/k;-><init>(JLcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;Lkotlin/coroutines/Continuation;)V

    .line 80
    .line 81
    .line 82
    invoke-static {v0, v4, v4, v3, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    iput-object v0, p0, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->j:Lvy0/x1;

    .line 87
    .line 88
    goto :goto_1

    .line 89
    :cond_3
    const-string v0, "curNotification"

    .line 90
    .line 91
    invoke-static {v0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    throw v4

    .line 95
    :cond_4
    const-string v2, "Stop"

    .line 96
    .line 97
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result v0

    .line 101
    if-eqz v0, :cond_5

    .line 102
    .line 103
    new-instance v0, Lr40/b;

    .line 104
    .line 105
    const/4 v6, 0x0

    .line 106
    const/16 v7, 0x9

    .line 107
    .line 108
    const/4 v1, 0x0

    .line 109
    const-class v3, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;

    .line 110
    .line 111
    const-string v4, "stopSelf"

    .line 112
    .line 113
    const-string v5, "stopSelf()V"

    .line 114
    .line 115
    move-object v2, p0

    .line 116
    invoke-direct/range {v0 .. v7}, Lr40/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 117
    .line 118
    .line 119
    iget-object v2, p0, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->f:Ljava/lang/Object;

    .line 120
    .line 121
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v2

    .line 125
    check-cast v2, Lo40/y;

    .line 126
    .line 127
    sget-object v3, Lon0/h;->f:Lon0/h;

    .line 128
    .line 129
    invoke-virtual {v2, v3}, Lo40/y;->a(Lon0/h;)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v0}, Lr40/b;->invoke()Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    :cond_5
    :goto_1
    invoke-super/range {p0 .. p3}, Landroid/app/Service;->onStartCommand(Landroid/content/Intent;II)I

    .line 136
    .line 137
    .line 138
    move-result v0

    .line 139
    return v0
.end method
