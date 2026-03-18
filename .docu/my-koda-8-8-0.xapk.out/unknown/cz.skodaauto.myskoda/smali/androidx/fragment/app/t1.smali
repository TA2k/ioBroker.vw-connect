.class public final Landroidx/fragment/app/t1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:I

.field public b:Landroidx/fragment/app/j0;

.field public c:Z

.field public d:I

.field public e:I

.field public f:I

.field public g:I

.field public h:Landroidx/lifecycle/q;

.field public i:Landroidx/lifecycle/q;


# direct methods
.method public constructor <init>(ILandroidx/fragment/app/j0;I)V
    .locals 0

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    iput p1, p0, Landroidx/fragment/app/t1;->a:I

    .line 9
    iput-object p2, p0, Landroidx/fragment/app/t1;->b:Landroidx/fragment/app/j0;

    const/4 p1, 0x1

    .line 10
    iput-boolean p1, p0, Landroidx/fragment/app/t1;->c:Z

    .line 11
    sget-object p1, Landroidx/lifecycle/q;->h:Landroidx/lifecycle/q;

    iput-object p1, p0, Landroidx/fragment/app/t1;->h:Landroidx/lifecycle/q;

    .line 12
    iput-object p1, p0, Landroidx/fragment/app/t1;->i:Landroidx/lifecycle/q;

    return-void
.end method

.method public constructor <init>(Landroidx/fragment/app/j0;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput p2, p0, Landroidx/fragment/app/t1;->a:I

    .line 3
    iput-object p1, p0, Landroidx/fragment/app/t1;->b:Landroidx/fragment/app/j0;

    const/4 p1, 0x0

    .line 4
    iput-boolean p1, p0, Landroidx/fragment/app/t1;->c:Z

    .line 5
    sget-object p1, Landroidx/lifecycle/q;->h:Landroidx/lifecycle/q;

    iput-object p1, p0, Landroidx/fragment/app/t1;->h:Landroidx/lifecycle/q;

    .line 6
    iput-object p1, p0, Landroidx/fragment/app/t1;->i:Landroidx/lifecycle/q;

    return-void
.end method
