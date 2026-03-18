.class public final synthetic Lms/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:J

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lb81/b;Ljava/lang/Object;J)V
    .locals 1

    .line 1
    const/4 v0, 0x2

    iput v0, p0, Lms/o;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lms/o;->e:Ljava/lang/Object;

    iput-object p2, p0, Lms/o;->g:Ljava/lang/Object;

    iput-wide p3, p0, Lms/o;->f:J

    return-void
.end method

.method public synthetic constructor <init>(Lms/p;JLjava/lang/String;I)V
    .locals 0

    .line 2
    iput p5, p0, Lms/o;->d:I

    iput-object p1, p0, Lms/o;->e:Ljava/lang/Object;

    iput-wide p2, p0, Lms/o;->f:J

    iput-object p4, p0, Lms/o;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 10

    .line 1
    iget v0, p0, Lms/o;->d:I

    .line 2
    .line 3
    iget-wide v1, p0, Lms/o;->f:J

    .line 4
    .line 5
    iget-object v3, p0, Lms/o;->g:Ljava/lang/Object;

    .line 6
    .line 7
    iget-object v4, p0, Lms/o;->e:Ljava/lang/Object;

    .line 8
    .line 9
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    check-cast v4, Lb81/b;

    .line 13
    .line 14
    iget-object p0, v4, Lb81/b;->f:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, La8/f0;

    .line 17
    .line 18
    sget-object v0, Lw7/w;->a:Ljava/lang/String;

    .line 19
    .line 20
    iget-object p0, p0, La8/f0;->d:La8/i0;

    .line 21
    .line 22
    iget-object v0, p0, La8/i0;->w:Lb8/e;

    .line 23
    .line 24
    invoke-virtual {v0}, Lb8/e;->L()Lb8/a;

    .line 25
    .line 26
    .line 27
    move-result-object v4

    .line 28
    new-instance v5, Lb8/c;

    .line 29
    .line 30
    invoke-direct {v5, v4, v3, v1, v2}, Lb8/c;-><init>(Lb8/a;Ljava/lang/Object;J)V

    .line 31
    .line 32
    .line 33
    const/16 v1, 0x1a

    .line 34
    .line 35
    invoke-virtual {v0, v4, v1, v5}, Lb8/e;->M(Lb8/a;ILw7/j;)V

    .line 36
    .line 37
    .line 38
    iget-object v0, p0, La8/i0;->Y:Ljava/lang/Object;

    .line 39
    .line 40
    if-ne v0, v3, :cond_0

    .line 41
    .line 42
    iget-object p0, p0, La8/i0;->q:Le30/v;

    .line 43
    .line 44
    new-instance v0, La6/a;

    .line 45
    .line 46
    const/4 v2, 0x4

    .line 47
    invoke-direct {v0, v2}, La6/a;-><init>(I)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {p0, v1, v0}, Le30/v;->e(ILw7/j;)V

    .line 51
    .line 52
    .line 53
    :cond_0
    return-void

    .line 54
    :pswitch_0
    check-cast v4, Lms/p;

    .line 55
    .line 56
    check-cast v3, Ljava/lang/String;

    .line 57
    .line 58
    iget-object p0, v4, Lms/p;->h:Lms/l;

    .line 59
    .line 60
    iget-object v0, p0, Lms/l;->n:Lms/r;

    .line 61
    .line 62
    if-eqz v0, :cond_1

    .line 63
    .line 64
    iget-object v0, v0, Lms/r;->e:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 65
    .line 66
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 67
    .line 68
    .line 69
    move-result v0

    .line 70
    if-eqz v0, :cond_1

    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_1
    iget-object p0, p0, Lms/l;->i:Los/f;

    .line 74
    .line 75
    iget-object p0, p0, Los/f;->e:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast p0, Los/d;

    .line 78
    .line 79
    invoke-interface {p0, v1, v2, v3}, Los/d;->d(JLjava/lang/String;)V

    .line 80
    .line 81
    .line 82
    :goto_0
    return-void

    .line 83
    :pswitch_1
    move-object v5, v4

    .line 84
    check-cast v5, Lms/p;

    .line 85
    .line 86
    move-object v8, v3

    .line 87
    check-cast v8, Ljava/lang/String;

    .line 88
    .line 89
    iget-object v0, v5, Lms/p;->p:Lns/d;

    .line 90
    .line 91
    iget-object v0, v0, Lns/d;->b:Lns/b;

    .line 92
    .line 93
    new-instance v4, Lms/o;

    .line 94
    .line 95
    const/4 v9, 0x1

    .line 96
    iget-wide v6, p0, Lms/o;->f:J

    .line 97
    .line 98
    invoke-direct/range {v4 .. v9}, Lms/o;-><init>(Lms/p;JLjava/lang/String;I)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {v0, v4}, Lns/b;->a(Ljava/lang/Runnable;)Laq/t;

    .line 102
    .line 103
    .line 104
    return-void

    .line 105
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
