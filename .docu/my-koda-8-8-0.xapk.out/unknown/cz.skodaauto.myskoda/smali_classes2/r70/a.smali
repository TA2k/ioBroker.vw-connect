.class public final Lr70/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkj0/b;


# static fields
.field public static final a:Lr70/a;

.field public static final b:Ljava/util/Set;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lr70/a;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lr70/a;->a:Lr70/a;

    .line 7
    .line 8
    new-instance v0, Llx0/l;

    .line 9
    .line 10
    const-string v1, "value"

    .line 11
    .line 12
    const-string v2, "true"

    .line 13
    .line 14
    invoke-direct {v0, v1, v2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    invoke-static {v0}, Ljp/m1;->k(Ljava/lang/Object;)Ljava/util/Set;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    sput-object v0, Lr70/a;->b:Ljava/util/Set;

    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final getName()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "rooted_device"

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParams()Ljava/util/Set;
    .locals 0

    .line 1
    sget-object p0, Lr70/a;->b:Ljava/util/Set;

    .line 2
    .line 3
    return-object p0
.end method
