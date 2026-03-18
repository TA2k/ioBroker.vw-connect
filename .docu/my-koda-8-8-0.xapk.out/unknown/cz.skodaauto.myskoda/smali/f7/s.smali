.class public final Lf7/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lf7/s;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lf7/s;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lf7/s;->a:Lf7/s;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ly6/q;)Ly6/q;
    .locals 1

    .line 1
    new-instance p0, Lf7/t;

    .line 2
    .line 3
    sget-object v0, Lk7/d;->a:Lk7/d;

    .line 4
    .line 5
    invoke-direct {p0, v0}, Lf7/t;-><init>(Lk7/g;)V

    .line 6
    .line 7
    .line 8
    invoke-interface {p1, p0}, Ly6/q;->d(Ly6/q;)Ly6/q;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method
