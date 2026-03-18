.class public final Lcom/google/crypto/tink/shaded/protobuf/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final b:Lcom/google/crypto/tink/shaded/protobuf/u;


# instance fields
.field public final a:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/google/crypto/tink/shaded/protobuf/u;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/u;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/google/crypto/tink/shaded/protobuf/m;->b:Lcom/google/crypto/tink/shaded/protobuf/u;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 5

    .line 4
    new-instance v0, Lcom/google/crypto/tink/shaded/protobuf/l0;

    .line 5
    :try_start_0
    const-string v1, "com.google.crypto.tink.shaded.protobuf.DescriptorMessageInfoFactory"

    invoke-static {v1}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v1

    .line 6
    const-string v2, "getInstance"

    const/4 v3, 0x0

    invoke-virtual {v1, v2, v3}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v1

    invoke-virtual {v1, v3, v3}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lcom/google/crypto/tink/shaded/protobuf/p0;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    .line 7
    :catch_0
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/m;->b:Lcom/google/crypto/tink/shaded/protobuf/u;

    :goto_0
    const/4 v2, 0x2

    .line 8
    new-array v2, v2, [Lcom/google/crypto/tink/shaded/protobuf/p0;

    sget-object v3, Lcom/google/crypto/tink/shaded/protobuf/u;->b:Lcom/google/crypto/tink/shaded/protobuf/u;

    const/4 v4, 0x0

    aput-object v3, v2, v4

    const/4 v3, 0x1

    aput-object v1, v2, v3

    .line 9
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 10
    iput-object v2, v0, Lcom/google/crypto/tink/shaded/protobuf/l0;->a:[Lcom/google/crypto/tink/shaded/protobuf/p0;

    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/b0;->a:Ljava/nio/charset/Charset;

    iput-object v0, p0, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lcom/google/crypto/tink/shaded/protobuf/k;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    const-string v0, "output"

    invoke-static {p1, v0}, Lcom/google/crypto/tink/shaded/protobuf/b0;->a(Ljava/lang/Object;Ljava/lang/String;)V

    iput-object p1, p0, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 3
    iput-object p0, p1, Lcom/google/crypto/tink/shaded/protobuf/k;->a:Lcom/google/crypto/tink/shaded/protobuf/m;

    return-void
.end method


# virtual methods
.method public a(ILcom/google/crypto/tink/shaded/protobuf/i;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 4
    .line 5
    const/4 v0, 0x2

    .line 6
    invoke-virtual {p0, p1, v0}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p2}, Lcom/google/crypto/tink/shaded/protobuf/i;->size()I

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    invoke-virtual {p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/k;->R(I)V

    .line 14
    .line 15
    .line 16
    check-cast p2, Lcom/google/crypto/tink/shaded/protobuf/h;

    .line 17
    .line 18
    iget-object p1, p2, Lcom/google/crypto/tink/shaded/protobuf/h;->g:[B

    .line 19
    .line 20
    invoke-virtual {p2}, Lcom/google/crypto/tink/shaded/protobuf/h;->m()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    invoke-virtual {p2}, Lcom/google/crypto/tink/shaded/protobuf/h;->size()I

    .line 25
    .line 26
    .line 27
    move-result p2

    .line 28
    invoke-virtual {p0, p1, v0, p2}, Lcom/google/crypto/tink/shaded/protobuf/k;->K([BII)V

    .line 29
    .line 30
    .line 31
    return-void
.end method

.method public b(ILjava/lang/Object;Lcom/google/crypto/tink/shaded/protobuf/a1;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 4
    .line 5
    check-cast p2, Lcom/google/crypto/tink/shaded/protobuf/a;

    .line 6
    .line 7
    const/4 v0, 0x3

    .line 8
    invoke-virtual {p0, p1, v0}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->a:Lcom/google/crypto/tink/shaded/protobuf/m;

    .line 12
    .line 13
    invoke-interface {p3, p2, v0}, Lcom/google/crypto/tink/shaded/protobuf/a1;->d(Ljava/lang/Object;Lcom/google/crypto/tink/shaded/protobuf/m;)V

    .line 14
    .line 15
    .line 16
    const/4 p2, 0x4

    .line 17
    invoke-virtual {p0, p1, p2}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public c(ILjava/lang/Object;Lcom/google/crypto/tink/shaded/protobuf/a1;)V
    .locals 2

    .line 1
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 4
    .line 5
    check-cast p2, Lcom/google/crypto/tink/shaded/protobuf/a;

    .line 6
    .line 7
    const/4 v0, 0x2

    .line 8
    invoke-virtual {p0, p1, v0}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    move-object p1, p2

    .line 15
    check-cast p1, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 16
    .line 17
    iget v0, p1, Lcom/google/crypto/tink/shaded/protobuf/x;->memoizedSerializedSize:I

    .line 18
    .line 19
    const/4 v1, -0x1

    .line 20
    if-ne v0, v1, :cond_0

    .line 21
    .line 22
    invoke-interface {p3, p2}, Lcom/google/crypto/tink/shaded/protobuf/a1;->i(Lcom/google/crypto/tink/shaded/protobuf/a;)I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    iput v0, p1, Lcom/google/crypto/tink/shaded/protobuf/x;->memoizedSerializedSize:I

    .line 27
    .line 28
    :cond_0
    invoke-virtual {p0, v0}, Lcom/google/crypto/tink/shaded/protobuf/k;->R(I)V

    .line 29
    .line 30
    .line 31
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->a:Lcom/google/crypto/tink/shaded/protobuf/m;

    .line 32
    .line 33
    invoke-interface {p3, p2, p0}, Lcom/google/crypto/tink/shaded/protobuf/a1;->d(Ljava/lang/Object;Lcom/google/crypto/tink/shaded/protobuf/m;)V

    .line 34
    .line 35
    .line 36
    return-void
.end method
