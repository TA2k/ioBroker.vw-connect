.class public final Lb1/p;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:Lb1/r;

.field public final synthetic g:Lt3/e1;

.field public final synthetic h:J


# direct methods
.method public constructor <init>(Lb1/r;Lt3/e1;J)V
    .locals 0

    .line 1
    iput-object p1, p0, Lb1/p;->f:Lb1/r;

    .line 2
    .line 3
    iput-object p2, p0, Lb1/p;->g:Lt3/e1;

    .line 4
    .line 5
    iput-wide p3, p0, Lb1/p;->h:J

    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    check-cast p1, Lt3/d1;

    .line 2
    .line 3
    iget-object v0, p0, Lb1/p;->f:Lb1/r;

    .line 4
    .line 5
    iget-object v0, v0, Lb1/r;->u:Lb1/t;

    .line 6
    .line 7
    iget-object v1, v0, Lb1/t;->b:Lx2/e;

    .line 8
    .line 9
    iget-object v0, p0, Lb1/p;->g:Lt3/e1;

    .line 10
    .line 11
    iget v2, v0, Lt3/e1;->d:I

    .line 12
    .line 13
    iget v3, v0, Lt3/e1;->e:I

    .line 14
    .line 15
    int-to-long v4, v2

    .line 16
    const/16 v2, 0x20

    .line 17
    .line 18
    shl-long/2addr v4, v2

    .line 19
    int-to-long v2, v3

    .line 20
    const-wide v6, 0xffffffffL

    .line 21
    .line 22
    .line 23
    .line 24
    .line 25
    and-long/2addr v2, v6

    .line 26
    or-long/2addr v2, v4

    .line 27
    iget-wide v4, p0, Lb1/p;->h:J

    .line 28
    .line 29
    sget-object v6, Lt4/m;->d:Lt4/m;

    .line 30
    .line 31
    invoke-interface/range {v1 .. v6}, Lx2/e;->a(JJLt4/m;)J

    .line 32
    .line 33
    .line 34
    move-result-wide v1

    .line 35
    invoke-static {p1, v0, v1, v2}, Lt3/d1;->i(Lt3/d1;Lt3/e1;J)V

    .line 36
    .line 37
    .line 38
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 39
    .line 40
    return-object p0
.end method
