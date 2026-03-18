.class public final Lx71/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Lio/o;

.field public b:Lio/o;

.field public final c:Lx71/h;


# direct methods
.method public constructor <init>(Lio/o;Lio/o;Lx71/h;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lx71/g;->a:Lio/o;

    .line 5
    .line 6
    iput-object p2, p0, Lx71/g;->b:Lio/o;

    .line 7
    .line 8
    new-instance p1, Lx71/h;

    .line 9
    .line 10
    invoke-direct {p1}, Lx71/h;-><init>()V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lx71/g;->c:Lx71/h;

    .line 14
    .line 15
    iget-wide v0, p3, Lx71/h;->a:J

    .line 16
    .line 17
    iput-wide v0, p1, Lx71/h;->a:J

    .line 18
    .line 19
    iget-wide p2, p3, Lx71/h;->b:J

    .line 20
    .line 21
    iput-wide p2, p1, Lx71/h;->b:J

    .line 22
    .line 23
    return-void
.end method
