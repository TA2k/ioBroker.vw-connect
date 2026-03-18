.class public abstract Lcom/contoworks/kontocloud/uicomponents/widget/CompoundView;
.super Landroid/widget/FrameLayout;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private uiHandler:Landroid/os/Handler;

.field private view:Landroid/view/View;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Landroid/widget/FrameLayout;-><init>(Landroid/content/Context;)V

    .line 2
    new-instance p1, Landroid/os/Handler;

    invoke-direct {p1}, Landroid/os/Handler;-><init>()V

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CompoundView;->uiHandler:Landroid/os/Handler;

    .line 3
    invoke-direct {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/CompoundView;->initializeViews()V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 0

    .line 4
    invoke-direct {p0, p1, p2}, Landroid/widget/FrameLayout;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    .line 5
    new-instance p1, Landroid/os/Handler;

    invoke-direct {p1}, Landroid/os/Handler;-><init>()V

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CompoundView;->uiHandler:Landroid/os/Handler;

    .line 6
    invoke-direct {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/CompoundView;->initializeViews()V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V
    .locals 0

    .line 7
    invoke-direct {p0, p1, p2, p3}, Landroid/widget/FrameLayout;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    .line 8
    new-instance p1, Landroid/os/Handler;

    invoke-direct {p1}, Landroid/os/Handler;-><init>()V

    iput-object p1, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CompoundView;->uiHandler:Landroid/os/Handler;

    .line 9
    invoke-direct {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/CompoundView;->initializeViews()V

    return-void
.end method

.method private initializeViews()V
    .locals 2

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-string v1, "layout_inflater"

    .line 6
    .line 7
    invoke-virtual {v0, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    check-cast v0, Landroid/view/LayoutInflater;

    .line 12
    .line 13
    invoke-virtual {p0}, Lcom/contoworks/kontocloud/uicomponents/widget/CompoundView;->getLayoutId()I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    invoke-virtual {v0, v1, p0}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;)Landroid/view/View;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    iput-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CompoundView;->view:Landroid/view/View;

    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public abstract getLayoutId()I
.end method

.method public getUiHandler()Landroid/os/Handler;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CompoundView;->uiHandler:Landroid/os/Handler;

    .line 2
    .line 3
    return-object p0
.end method

.method public onFinishInflate()V
    .locals 1

    .line 1
    invoke-super {p0}, Landroid/view/View;->onFinishInflate()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lcom/contoworks/kontocloud/uicomponents/widget/CompoundView;->view:Landroid/view/View;

    .line 5
    .line 6
    invoke-virtual {p0, v0}, Lcom/contoworks/kontocloud/uicomponents/widget/CompoundView;->onViewCreated(Landroid/view/View;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public abstract onViewCreated(Landroid/view/View;)V
.end method
