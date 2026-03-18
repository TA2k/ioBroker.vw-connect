.class public final Ld01/p0;
.super Ld01/r0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Ld01/d0;

.field public final synthetic b:I

.field public final synthetic c:[B

.field public final synthetic d:I


# direct methods
.method public constructor <init>(Ld01/d0;[BII)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ld01/p0;->a:Ld01/d0;

    .line 5
    .line 6
    iput p3, p0, Ld01/p0;->b:I

    .line 7
    .line 8
    iput-object p2, p0, Ld01/p0;->c:[B

    .line 9
    .line 10
    iput p4, p0, Ld01/p0;->d:I

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final contentLength()J
    .locals 2

    .line 1
    iget p0, p0, Ld01/p0;->b:I

    .line 2
    .line 3
    int-to-long v0, p0

    .line 4
    return-wide v0
.end method

.method public final contentType()Ld01/d0;
    .locals 0

    .line 1
    iget-object p0, p0, Ld01/p0;->a:Ld01/d0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final writeTo(Lu01/g;)V
    .locals 2

    .line 1
    iget v0, p0, Ld01/p0;->d:I

    .line 2
    .line 3
    iget v1, p0, Ld01/p0;->b:I

    .line 4
    .line 5
    iget-object p0, p0, Ld01/p0;->c:[B

    .line 6
    .line 7
    invoke-interface {p1, p0, v0, v1}, Lu01/g;->write([BII)Lu01/g;

    .line 8
    .line 9
    .line 10
    return-void
.end method
