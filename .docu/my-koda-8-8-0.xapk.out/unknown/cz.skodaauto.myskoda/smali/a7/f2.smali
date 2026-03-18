.class public final La7/f2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:La7/f2;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, La7/f2;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, La7/f2;->a:La7/f2;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lk7/g;)Lc7/b;
    .locals 0

    .line 1
    instance-of p0, p1, Lk7/d;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lc7/b;->h:Lc7/b;

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    sget-object p0, Lc7/b;->f:Lc7/b;

    .line 9
    .line 10
    return-object p0
.end method
