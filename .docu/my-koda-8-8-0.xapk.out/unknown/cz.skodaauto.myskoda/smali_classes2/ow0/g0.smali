.class public final Low0/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqz0/a;


# static fields
.field public static final a:Low0/g0;

.field public static final b:Luz0/h1;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Low0/g0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Low0/g0;->a:Low0/g0;

    .line 7
    .line 8
    const-string v0, "io.ktor.http.Url"

    .line 9
    .line 10
    invoke-static {v0}, Lkp/x8;->a(Ljava/lang/String;)Luz0/h1;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    sput-object v0, Low0/g0;->b:Luz0/h1;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-interface {p1}, Ltz0/c;->x()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Ljp/sc;->d(Ljava/lang/String;)Low0/f0;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Low0/g0;->b:Luz0/h1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p2, Low0/f0;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p2, Low0/f0;->h:Ljava/lang/String;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->E(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method
