.class public final Lmr/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/Object;

.field public final b:[B

.field public final c:Lqr/r;

.field public final d:Lqr/d0;


# direct methods
.method public constructor <init>(Ljava/lang/Object;[BLqr/r;Lqr/d0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lmr/c;->a:Ljava/lang/Object;

    .line 5
    .line 6
    array-length p1, p2

    .line 7
    invoke-static {p2, p1}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    iput-object p1, p0, Lmr/c;->b:[B

    .line 12
    .line 13
    iput-object p3, p0, Lmr/c;->c:Lqr/r;

    .line 14
    .line 15
    iput-object p4, p0, Lmr/c;->d:Lqr/d0;

    .line 16
    .line 17
    return-void
.end method
