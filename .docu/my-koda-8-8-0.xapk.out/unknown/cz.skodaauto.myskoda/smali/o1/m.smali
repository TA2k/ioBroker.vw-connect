.class public final Lo1/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/e;


# instance fields
.field public final synthetic a:Lo1/n;

.field public final synthetic b:Lkotlin/jvm/internal/f0;

.field public final synthetic c:I


# direct methods
.method public constructor <init>(Lo1/n;Lkotlin/jvm/internal/f0;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lo1/m;->a:Lo1/n;

    .line 5
    .line 6
    iput-object p2, p0, Lo1/m;->b:Lkotlin/jvm/internal/f0;

    .line 7
    .line 8
    iput p3, p0, Lo1/m;->c:I

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a()Z
    .locals 2

    .line 1
    iget-object v0, p0, Lo1/m;->b:Lkotlin/jvm/internal/f0;

    .line 2
    .line 3
    iget-object v0, v0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, Lo1/k;

    .line 6
    .line 7
    iget v1, p0, Lo1/m;->c:I

    .line 8
    .line 9
    iget-object p0, p0, Lo1/m;->a:Lo1/n;

    .line 10
    .line 11
    invoke-virtual {p0, v0, v1}, Lo1/n;->X0(Lo1/k;I)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0
.end method
