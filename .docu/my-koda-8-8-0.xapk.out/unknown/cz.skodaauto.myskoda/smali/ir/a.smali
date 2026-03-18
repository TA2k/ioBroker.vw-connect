.class public final Lir/a;
.super Ljava/io/OutputStream;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "ByteStreams.nullOutputStream()"

    .line 2
    .line 3
    return-object p0
.end method

.method public final write(I)V
    .locals 0

    .line 1
    return-void
.end method

.method public final write([B)V
    .locals 0

    .line 2
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    return-void
.end method

.method public final write([BII)V
    .locals 0

    .line 3
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    add-int/2addr p3, p2

    .line 4
    array-length p0, p1

    invoke-static {p2, p3, p0}, Lkp/i9;->g(III)V

    return-void
.end method
