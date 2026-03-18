.class public final Lpt/e;
.super Landroidx/fragment/app/e1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final f:Lst/a;


# instance fields
.field public final a:Ljava/util/WeakHashMap;

.field public final b:La61/a;

.field public final c:Lyt/h;

.field public final d:Lpt/c;

.field public final e:Lpt/f;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lst/a;->d()Lst/a;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lpt/e;->f:Lst/a;

    .line 6
    .line 7
    return-void
.end method

.method public constructor <init>(La61/a;Lyt/h;Lpt/c;Lpt/f;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/WeakHashMap;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/WeakHashMap;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lpt/e;->a:Ljava/util/WeakHashMap;

    .line 10
    .line 11
    iput-object p1, p0, Lpt/e;->b:La61/a;

    .line 12
    .line 13
    iput-object p2, p0, Lpt/e;->c:Lyt/h;

    .line 14
    .line 15
    iput-object p3, p0, Lpt/e;->d:Lpt/c;

    .line 16
    .line 17
    iput-object p4, p0, Lpt/e;->e:Lpt/f;

    .line 18
    .line 19
    return-void
.end method
