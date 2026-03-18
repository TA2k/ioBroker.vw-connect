.class public final Llj0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkj0/b;


# static fields
.field public static final a:Llj0/c;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Llj0/c;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Llj0/c;->a:Llj0/c;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final getName()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "pulldown_to_refresh"

    .line 2
    .line 3
    return-object p0
.end method

.method public final getParams()Ljava/util/Set;
    .locals 0

    .line 1
    sget-object p0, Lmx0/u;->d:Lmx0/u;

    .line 2
    .line 3
    return-object p0
.end method
