.class public final Lvp/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:J

.field public final synthetic f:Lvp/x;


# direct methods
.method public constructor <init>(Lvp/u2;J)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lvp/v;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-wide p2, p0, Lvp/v;->e:J

    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Lvp/v;->f:Lvp/x;

    return-void
.end method

.method public constructor <init>(Lvp/w;J)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lvp/v;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-wide p2, p0, Lvp/v;->e:J

    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Lvp/v;->f:Lvp/x;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 4

    .line 1
    iget v0, p0, Lvp/v;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lvp/v;->f:Lvp/x;

    .line 7
    .line 8
    check-cast v0, Lvp/u2;

    .line 9
    .line 10
    iget-object v1, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lvp/g1;

    .line 13
    .line 14
    iget-object v1, v1, Lvp/g1;->q:Lvp/w;

    .line 15
    .line 16
    invoke-static {v1}, Lvp/g1;->e(Lvp/x;)V

    .line 17
    .line 18
    .line 19
    iget-wide v2, p0, Lvp/v;->e:J

    .line 20
    .line 21
    invoke-virtual {v1, v2, v3}, Lvp/w;->d0(J)V

    .line 22
    .line 23
    .line 24
    const/4 p0, 0x0

    .line 25
    iput-object p0, v0, Lvp/u2;->i:Lvp/r2;

    .line 26
    .line 27
    return-void

    .line 28
    :pswitch_0
    iget-object v0, p0, Lvp/v;->f:Lvp/x;

    .line 29
    .line 30
    check-cast v0, Lvp/w;

    .line 31
    .line 32
    iget-wide v1, p0, Lvp/v;->e:J

    .line 33
    .line 34
    invoke-virtual {v0, v1, v2}, Lvp/w;->g0(J)V

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
