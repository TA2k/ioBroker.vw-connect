.class public final Lrt0/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# static fields
.field public static final b:Ljava/util/Set;


# instance fields
.field public final a:Lyb0/l;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-string v0, "access"

    .line 2
    .line 3
    const-string v1, "lights"

    .line 4
    .line 5
    filled-new-array {v0, v1}, [Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    sput-object v0, Lrt0/q;->b:Ljava/util/Set;

    .line 14
    .line 15
    return-void
.end method

.method public constructor <init>(Lyb0/l;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lrt0/q;->a:Lyb0/l;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    new-instance v0, Lyb0/i;

    .line 2
    .line 3
    sget-object v1, Lzb0/d;->e:Lzb0/d;

    .line 4
    .line 5
    const/4 v4, 0x0

    .line 6
    const/16 v5, 0x38

    .line 7
    .line 8
    const-string v2, "vehicle-status"

    .line 9
    .line 10
    sget-object v3, Lrt0/q;->b:Ljava/util/Set;

    .line 11
    .line 12
    invoke-direct/range {v0 .. v5}, Lyb0/i;-><init>(Lzb0/d;Ljava/lang/String;Ljava/util/Set;Lyb0/h;I)V

    .line 13
    .line 14
    .line 15
    iget-object p0, p0, Lrt0/q;->a:Lyb0/l;

    .line 16
    .line 17
    invoke-virtual {p0, v0}, Lyb0/l;->a(Lyb0/i;)Lzy0/j;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    new-instance v0, Lal0/j0;

    .line 22
    .line 23
    const/16 v1, 0x8

    .line 24
    .line 25
    invoke-direct {v0, p0, v1}, Lal0/j0;-><init>(Lzy0/j;I)V

    .line 26
    .line 27
    .line 28
    return-object v0
.end method
