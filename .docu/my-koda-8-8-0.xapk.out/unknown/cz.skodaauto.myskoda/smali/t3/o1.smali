.class public final Lt3/o1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lt3/q1;

.field public b:Lt3/m0;

.field public final c:Lt3/n1;

.field public final d:Lt3/n1;

.field public final e:Lt3/n1;


# direct methods
.method public constructor <init>(Lt3/q1;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt3/o1;->a:Lt3/q1;

    .line 5
    .line 6
    new-instance p1, Lt3/n1;

    .line 7
    .line 8
    const/4 v0, 0x2

    .line 9
    invoke-direct {p1, p0, v0}, Lt3/n1;-><init>(Lt3/o1;I)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Lt3/o1;->c:Lt3/n1;

    .line 13
    .line 14
    new-instance p1, Lt3/n1;

    .line 15
    .line 16
    const/4 v0, 0x0

    .line 17
    invoke-direct {p1, p0, v0}, Lt3/n1;-><init>(Lt3/o1;I)V

    .line 18
    .line 19
    .line 20
    iput-object p1, p0, Lt3/o1;->d:Lt3/n1;

    .line 21
    .line 22
    new-instance p1, Lt3/n1;

    .line 23
    .line 24
    const/4 v0, 0x1

    .line 25
    invoke-direct {p1, p0, v0}, Lt3/n1;-><init>(Lt3/o1;I)V

    .line 26
    .line 27
    .line 28
    iput-object p1, p0, Lt3/o1;->e:Lt3/n1;

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final a()Lt3/m0;
    .locals 1

    .line 1
    iget-object p0, p0, Lt3/o1;->b:Lt3/m0;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 7
    .line 8
    const-string v0, "SubcomposeLayoutState is not attached to SubcomposeLayout"

    .line 9
    .line 10
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method
