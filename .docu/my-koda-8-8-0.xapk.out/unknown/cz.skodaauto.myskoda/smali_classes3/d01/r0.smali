.class public abstract Ld01/r0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final Companion:Ld01/q0;

.field public static final EMPTY:Ld01/r0;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ld01/q0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ld01/r0;->Companion:Ld01/q0;

    .line 7
    .line 8
    sget-object v0, Lu01/i;->g:Lu01/i;

    .line 9
    .line 10
    const-string v1, "<this>"

    .line 11
    .line 12
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    new-instance v1, Ld01/n0;

    .line 16
    .line 17
    const/4 v2, 0x0

    .line 18
    invoke-direct {v1, v2, v0}, Ld01/n0;-><init>(Ld01/d0;Lu01/i;)V

    .line 19
    .line 20
    .line 21
    sput-object v1, Ld01/r0;->EMPTY:Ld01/r0;

    .line 22
    .line 23
    return-void
.end method

.method public static final create(Ld01/d0;Ljava/io/File;)Ld01/r0;
    .locals 1
    .annotation runtime Llx0/c;
    .end annotation

    sget-object v0, Ld01/r0;->Companion:Ld01/q0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1
    const-string v0, "file"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    new-instance v0, Ld01/l0;

    invoke-direct {v0, p0, p1}, Ld01/l0;-><init>(Ld01/d0;Ljava/io/File;)V

    return-object v0
.end method

.method public static final create(Ld01/d0;Ljava/lang/String;)Ld01/r0;
    .locals 1
    .annotation runtime Llx0/c;
    .end annotation

    sget-object v0, Ld01/r0;->Companion:Ld01/q0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 3
    const-string v0, "content"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    invoke-static {p1, p0}, Ld01/q0;->b(Ljava/lang/String;Ld01/d0;)Ld01/p0;

    move-result-object p0

    return-object p0
.end method

.method public static final create(Ld01/d0;Lu01/i;)Ld01/r0;
    .locals 1
    .annotation runtime Llx0/c;
    .end annotation

    sget-object v0, Ld01/r0;->Companion:Ld01/q0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 5
    const-string v0, "content"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    new-instance v0, Ld01/n0;

    invoke-direct {v0, p0, p1}, Ld01/n0;-><init>(Ld01/d0;Lu01/i;)V

    return-object v0
.end method

.method public static final create(Ld01/d0;[B)Ld01/r0;
    .locals 2
    .annotation runtime Llx0/c;
    .end annotation

    sget-object v0, Ld01/r0;->Companion:Ld01/q0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    const-string v0, "content"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    .line 8
    array-length v1, p1

    .line 9
    invoke-static {p0, p1, v0, v1}, Ld01/q0;->a(Ld01/d0;[BII)Ld01/p0;

    move-result-object p0

    return-object p0
.end method

.method public static final create(Ld01/d0;[BI)Ld01/r0;
    .locals 1
    .annotation runtime Llx0/c;
    .end annotation

    sget-object v0, Ld01/r0;->Companion:Ld01/q0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    const-string v0, "content"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    array-length v0, p1

    .line 12
    invoke-static {p0, p1, p2, v0}, Ld01/q0;->a(Ld01/d0;[BII)Ld01/p0;

    move-result-object p0

    return-object p0
.end method

.method public static final create(Ld01/d0;[BII)Ld01/r0;
    .locals 1
    .annotation runtime Llx0/c;
    .end annotation

    sget-object v0, Ld01/r0;->Companion:Ld01/q0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v0, "content"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    invoke-static {p0, p1, p2, p3}, Ld01/q0;->a(Ld01/d0;[BII)Ld01/p0;

    move-result-object p0

    return-object p0
.end method

.method public static final create(Ljava/io/File;Ld01/d0;)Ld01/r0;
    .locals 1

    sget-object v0, Ld01/r0;->Companion:Ld01/q0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    new-instance v0, Ld01/l0;

    invoke-direct {v0, p1, p0}, Ld01/l0;-><init>(Ld01/d0;Ljava/io/File;)V

    return-object v0
.end method

.method public static final create(Ljava/io/FileDescriptor;Ld01/d0;)Ld01/r0;
    .locals 1

    sget-object v0, Ld01/r0;->Companion:Ld01/q0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    new-instance v0, Ld01/o0;

    invoke-direct {v0, p0, p1}, Ld01/o0;-><init>(Ljava/io/FileDescriptor;Ld01/d0;)V

    return-object v0
.end method

.method public static final create(Ljava/lang/String;Ld01/d0;)Ld01/r0;
    .locals 1

    .line 15
    sget-object v0, Ld01/r0;->Companion:Ld01/q0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p0, p1}, Ld01/q0;->b(Ljava/lang/String;Ld01/d0;)Ld01/p0;

    move-result-object p0

    return-object p0
.end method

.method public static final create(Lu01/i;Ld01/d0;)Ld01/r0;
    .locals 1

    sget-object v0, Ld01/r0;->Companion:Ld01/q0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    new-instance v0, Ld01/n0;

    invoke-direct {v0, p1, p0}, Ld01/n0;-><init>(Ld01/d0;Lu01/i;)V

    return-object v0
.end method

.method public static final create(Lu01/y;Lu01/k;Ld01/d0;)Ld01/r0;
    .locals 1

    sget-object v0, Ld01/r0;->Companion:Ld01/q0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 16
    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "fileSystem"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    new-instance v0, Ld01/m0;

    invoke-direct {v0, p0, p1, p2}, Ld01/m0;-><init>(Lu01/y;Lu01/k;Ld01/d0;)V

    return-object v0
.end method

.method public static final create([B)Ld01/r0;
    .locals 4

    sget-object v0, Ld01/r0;->Companion:Ld01/q0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    const-string v1, "<this>"

    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v1, 0x0

    const/4 v2, 0x7

    const/4 v3, 0x0

    invoke-static {v0, p0, v3, v1, v2}, Ld01/q0;->c(Ld01/q0;[BLd01/d0;II)Ld01/p0;

    move-result-object p0

    return-object p0
.end method

.method public static final create([BLd01/d0;)Ld01/r0;
    .locals 3

    sget-object v0, Ld01/r0;->Companion:Ld01/q0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 19
    const-string v1, "<this>"

    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v1, 0x0

    const/4 v2, 0x6

    invoke-static {v0, p0, p1, v1, v2}, Ld01/q0;->c(Ld01/q0;[BLd01/d0;II)Ld01/p0;

    move-result-object p0

    return-object p0
.end method

.method public static final create([BLd01/d0;I)Ld01/r0;
    .locals 2

    sget-object v0, Ld01/r0;->Companion:Ld01/q0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 20
    const-string v1, "<this>"

    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v1, 0x4

    invoke-static {v0, p0, p1, p2, v1}, Ld01/q0;->c(Ld01/q0;[BLd01/d0;II)Ld01/p0;

    move-result-object p0

    return-object p0
.end method

.method public static final create([BLd01/d0;II)Ld01/r0;
    .locals 1

    .line 21
    sget-object v0, Ld01/r0;->Companion:Ld01/q0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p1, p0, p2, p3}, Ld01/q0;->a(Ld01/d0;[BII)Ld01/p0;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public contentLength()J
    .locals 2

    .line 1
    const-wide/16 v0, -0x1

    .line 2
    .line 3
    return-wide v0
.end method

.method public abstract contentType()Ld01/d0;
.end method

.method public isDuplex()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public isOneShot()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final sha256()Lu01/i;
    .locals 2

    .line 1
    new-instance v0, Lu01/e;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lu01/q;

    .line 7
    .line 8
    invoke-direct {v1, v0}, Lu01/q;-><init>(Lu01/e;)V

    .line 9
    .line 10
    .line 11
    invoke-static {v1}, Lu01/b;->b(Lu01/f0;)Lu01/a0;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    :try_start_0
    invoke-virtual {p0, v0}, Ld01/r0;->writeTo(Lu01/g;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Lu01/a0;->close()V

    .line 19
    .line 20
    .line 21
    iget-object p0, v1, Lu01/q;->e:Ljava/security/MessageDigest;

    .line 22
    .line 23
    if-eqz p0, :cond_0

    .line 24
    .line 25
    invoke-virtual {p0}, Ljava/security/MessageDigest;->digest()[B

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    new-instance v0, Lu01/i;

    .line 30
    .line 31
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    invoke-direct {v0, p0}, Lu01/i;-><init>([B)V

    .line 35
    .line 36
    .line 37
    return-object v0

    .line 38
    :cond_0
    const/4 p0, 0x0

    .line 39
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    throw p0

    .line 43
    :catchall_0
    move-exception p0

    .line 44
    :try_start_1
    throw p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 45
    :catchall_1
    move-exception v1

    .line 46
    invoke-static {v0, p0}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 47
    .line 48
    .line 49
    throw v1
.end method

.method public abstract writeTo(Lu01/g;)V
.end method
