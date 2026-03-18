.class public final Lhu/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lzs/d;


# static fields
.field public static final a:Lhu/f;

.field public static final b:Lzs/c;

.field public static final c:Lzs/c;

.field public static final d:Lzs/c;

.field public static final e:Lzs/c;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lhu/f;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lhu/f;->a:Lhu/f;

    .line 7
    .line 8
    const-string v0, "processName"

    .line 9
    .line 10
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    sput-object v0, Lhu/f;->b:Lzs/c;

    .line 15
    .line 16
    const-string v0, "pid"

    .line 17
    .line 18
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    sput-object v0, Lhu/f;->c:Lzs/c;

    .line 23
    .line 24
    const-string v0, "importance"

    .line 25
    .line 26
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    sput-object v0, Lhu/f;->d:Lzs/c;

    .line 31
    .line 32
    const-string v0, "defaultProcess"

    .line 33
    .line 34
    invoke-static {v0}, Lzs/c;->b(Ljava/lang/String;)Lzs/c;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    sput-object v0, Lhu/f;->e:Lzs/c;

    .line 39
    .line 40
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 1

    .line 1
    check-cast p1, Lhu/b0;

    .line 2
    .line 3
    check-cast p2, Lzs/e;

    .line 4
    .line 5
    sget-object p0, Lhu/f;->b:Lzs/c;

    .line 6
    .line 7
    iget-object v0, p1, Lhu/b0;->a:Ljava/lang/String;

    .line 8
    .line 9
    invoke-interface {p2, p0, v0}, Lzs/e;->a(Lzs/c;Ljava/lang/Object;)Lzs/e;

    .line 10
    .line 11
    .line 12
    sget-object p0, Lhu/f;->c:Lzs/c;

    .line 13
    .line 14
    iget v0, p1, Lhu/b0;->b:I

    .line 15
    .line 16
    invoke-interface {p2, p0, v0}, Lzs/e;->g(Lzs/c;I)Lzs/e;

    .line 17
    .line 18
    .line 19
    sget-object p0, Lhu/f;->d:Lzs/c;

    .line 20
    .line 21
    iget v0, p1, Lhu/b0;->c:I

    .line 22
    .line 23
    invoke-interface {p2, p0, v0}, Lzs/e;->g(Lzs/c;I)Lzs/e;

    .line 24
    .line 25
    .line 26
    sget-object p0, Lhu/f;->e:Lzs/c;

    .line 27
    .line 28
    iget-boolean p1, p1, Lhu/b0;->d:Z

    .line 29
    .line 30
    invoke-interface {p2, p0, p1}, Lzs/e;->d(Lzs/c;Z)Lzs/e;

    .line 31
    .line 32
    .line 33
    return-void
.end method
