.class public final Landroidx/lifecycle/m0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/lifecycle/x;


# static fields
.field public static final k:Landroidx/lifecycle/m0;


# instance fields
.field public d:I

.field public e:I

.field public f:Z

.field public g:Z

.field public h:Landroid/os/Handler;

.field public final i:Landroidx/lifecycle/z;

.field public final j:La0/d;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Landroidx/lifecycle/m0;

    .line 2
    .line 3
    invoke-direct {v0}, Landroidx/lifecycle/m0;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Landroidx/lifecycle/m0;->k:Landroidx/lifecycle/m0;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x1

    .line 5
    iput-boolean v0, p0, Landroidx/lifecycle/m0;->f:Z

    .line 6
    .line 7
    iput-boolean v0, p0, Landroidx/lifecycle/m0;->g:Z

    .line 8
    .line 9
    new-instance v1, Landroidx/lifecycle/z;

    .line 10
    .line 11
    invoke-direct {v1, p0, v0}, Landroidx/lifecycle/z;-><init>(Landroidx/lifecycle/x;Z)V

    .line 12
    .line 13
    .line 14
    iput-object v1, p0, Landroidx/lifecycle/m0;->i:Landroidx/lifecycle/z;

    .line 15
    .line 16
    new-instance v0, La0/d;

    .line 17
    .line 18
    const/4 v1, 0x5

    .line 19
    invoke-direct {v0, p0, v1}, La0/d;-><init>(Ljava/lang/Object;I)V

    .line 20
    .line 21
    .line 22
    iput-object v0, p0, Landroidx/lifecycle/m0;->j:La0/d;

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final getLifecycle()Landroidx/lifecycle/r;
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/lifecycle/m0;->i:Landroidx/lifecycle/z;

    .line 2
    .line 3
    return-object p0
.end method
