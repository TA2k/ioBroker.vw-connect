.class public final La7/l1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Li7/g;


# static fields
.field public static final a:La7/l1;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, La7/l1;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, La7/l1;->a:La7/l1;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Landroid/content/Context;Ljava/lang/String;)Ljava/io/File;
    .locals 0

    .line 1
    invoke-static {p1, p2}, Llp/ye;->a(Landroid/content/Context;Ljava/lang/String;)Ljava/io/File;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final b(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object p0, Lc7/l;->a:Lc7/l;

    .line 2
    .line 3
    new-instance v0, La7/k1;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-direct {v0, p1, p2, v1}, La7/k1;-><init>(Landroid/content/Context;Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sget-object p1, Lvy0/p0;->a:Lcz0/e;

    .line 10
    .line 11
    sget-object p1, Lcz0/d;->e:Lcz0/d;

    .line 12
    .line 13
    invoke-static {}, Lvy0/e0;->f()Lvy0/z1;

    .line 14
    .line 15
    .line 16
    move-result-object p2

    .line 17
    invoke-virtual {p1, p2}, Lpx0/a;->plus(Lpx0/g;)Lpx0/g;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    invoke-static {p1}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    const/4 p2, 0x0

    .line 26
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 27
    .line 28
    invoke-static {p0, p2, v1, p1, v0}, Lfb/w;->a(Lm6/u0;Lb3/g;Ljava/util/List;Lpw0/a;Lay0/a;)Lm6/w;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method
