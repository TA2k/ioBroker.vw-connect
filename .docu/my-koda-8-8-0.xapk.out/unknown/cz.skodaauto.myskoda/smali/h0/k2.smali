.class public final Lh0/k2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lb0/m1;


# instance fields
.field public final b:J

.field public final c:Lb0/m1;


# direct methods
.method public constructor <init>(JLb0/m1;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-wide/16 v0, 0x0

    .line 5
    .line 6
    cmp-long v0, p1, v0

    .line 7
    .line 8
    if-ltz v0, :cond_0

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 v0, 0x0

    .line 13
    :goto_0
    const-string v1, "Timeout must be non-negative."

    .line 14
    .line 15
    invoke-static {v0, v1}, Ljp/ed;->b(ZLjava/lang/String;)V

    .line 16
    .line 17
    .line 18
    iput-wide p1, p0, Lh0/k2;->b:J

    .line 19
    .line 20
    iput-object p3, p0, Lh0/k2;->c:Lb0/m1;

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final a()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lh0/k2;->b:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final b(Lcom/google/crypto/tink/shaded/protobuf/d;)Lb0/l1;
    .locals 5

    .line 1
    iget-object v0, p0, Lh0/k2;->c:Lb0/m1;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Lb0/m1;->b(Lcom/google/crypto/tink/shaded/protobuf/d;)Lb0/l1;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-wide/16 v1, 0x0

    .line 8
    .line 9
    iget-wide v3, p0, Lh0/k2;->b:J

    .line 10
    .line 11
    cmp-long p0, v3, v1

    .line 12
    .line 13
    if-lez p0, :cond_0

    .line 14
    .line 15
    iget-wide p0, p1, Lcom/google/crypto/tink/shaded/protobuf/d;->b:J

    .line 16
    .line 17
    iget-wide v1, v0, Lb0/l1;->a:J

    .line 18
    .line 19
    sub-long/2addr v3, v1

    .line 20
    cmp-long p0, p0, v3

    .line 21
    .line 22
    if-ltz p0, :cond_0

    .line 23
    .line 24
    sget-object p0, Lb0/l1;->d:Lb0/l1;

    .line 25
    .line 26
    return-object p0

    .line 27
    :cond_0
    return-object v0
.end method
