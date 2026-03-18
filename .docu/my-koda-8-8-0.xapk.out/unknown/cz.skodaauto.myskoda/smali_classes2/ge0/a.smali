.class public final Lge0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvy0/b0;


# static fields
.field public static final d:Lge0/a;

.field public static final e:Lpx0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lge0/a;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lge0/a;->d:Lge0/a;

    .line 7
    .line 8
    sget-object v0, Lge0/b;->a:Lcz0/e;

    .line 9
    .line 10
    invoke-static {}, Lvy0/e0;->f()Lvy0/z1;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v0, v1}, Lpx0/a;->plus(Lpx0/g;)Lpx0/g;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    sput-object v0, Lge0/a;->e:Lpx0/g;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final getCoroutineContext()Lpx0/g;
    .locals 0

    .line 1
    sget-object p0, Lge0/a;->e:Lpx0/g;

    .line 2
    .line 3
    return-object p0
.end method
