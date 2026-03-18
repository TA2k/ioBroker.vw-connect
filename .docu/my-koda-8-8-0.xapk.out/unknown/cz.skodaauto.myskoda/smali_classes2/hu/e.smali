.class public final Lhu/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lzs/d;


# static fields
.field public static final a:Lhu/e;

.field public static final b:Lzs/c;

.field public static final c:Lzs/c;

.field public static final d:Lzs/c;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lhu/e;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lhu/e;->a:Lhu/e;

    .line 7
    .line 8
    const-string v0, "performance"

    .line 9
    .line 10
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    sput-object v0, Lhu/e;->b:Lzs/c;

    .line 15
    .line 16
    const-string v0, "crashlytics"

    .line 17
    .line 18
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    sput-object v0, Lhu/e;->c:Lzs/c;

    .line 23
    .line 24
    const-string v0, "sessionSamplingRate"

    .line 25
    .line 26
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    sput-object v0, Lhu/e;->d:Lzs/c;

    .line 31
    .line 32
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 2

    .line 1
    check-cast p1, Lhu/k;

    .line 2
    .line 3
    check-cast p2, Lzs/e;

    .line 4
    .line 5
    sget-object p0, Lhu/e;->b:Lzs/c;

    .line 6
    .line 7
    iget-object v0, p1, Lhu/k;->a:Lhu/j;

    .line 8
    .line 9
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 10
    .line 11
    .line 12
    sget-object p0, Lhu/e;->c:Lzs/c;

    .line 13
    .line 14
    iget-object v0, p1, Lhu/k;->b:Lhu/j;

    .line 15
    .line 16
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 17
    .line 18
    .line 19
    sget-object p0, Lhu/e;->d:Lzs/c;

    .line 20
    .line 21
    iget-wide v0, p1, Lhu/k;->c:D

    .line 22
    .line 23
    invoke-interface {p2, p0, v0, v1}, Lzs/e;->e(Lzs/c;D)Lzs/e;

    .line 24
    .line 25
    .line 26
    return-void
.end method
