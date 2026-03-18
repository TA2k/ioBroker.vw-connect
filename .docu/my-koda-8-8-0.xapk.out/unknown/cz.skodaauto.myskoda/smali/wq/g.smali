.class public Lwq/g;
.super Landroid/graphics/drawable/Drawable$ConstantState;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Lwq/m;

.field public b:Lwq/x;

.field public c:Lqq/a;

.field public d:Landroid/content/res/ColorStateList;

.field public e:Landroid/content/res/ColorStateList;

.field public f:Landroid/content/res/ColorStateList;

.field public g:Landroid/graphics/PorterDuff$Mode;

.field public h:Landroid/graphics/Rect;

.field public final i:F

.field public j:F

.field public k:F

.field public l:I

.field public m:F

.field public n:F

.field public o:I

.field public p:I

.field public final q:Landroid/graphics/Paint$Style;


# direct methods
.method public constructor <init>(Lwq/g;)V
    .locals 2

    .line 17
    invoke-direct {p0}, Landroid/graphics/drawable/Drawable$ConstantState;-><init>()V

    const/4 v0, 0x0

    .line 18
    iput-object v0, p0, Lwq/g;->d:Landroid/content/res/ColorStateList;

    .line 19
    iput-object v0, p0, Lwq/g;->e:Landroid/content/res/ColorStateList;

    .line 20
    iput-object v0, p0, Lwq/g;->f:Landroid/content/res/ColorStateList;

    .line 21
    sget-object v1, Landroid/graphics/PorterDuff$Mode;->SRC_IN:Landroid/graphics/PorterDuff$Mode;

    iput-object v1, p0, Lwq/g;->g:Landroid/graphics/PorterDuff$Mode;

    .line 22
    iput-object v0, p0, Lwq/g;->h:Landroid/graphics/Rect;

    const/high16 v0, 0x3f800000    # 1.0f

    .line 23
    iput v0, p0, Lwq/g;->i:F

    .line 24
    iput v0, p0, Lwq/g;->j:F

    const/16 v0, 0xff

    .line 25
    iput v0, p0, Lwq/g;->l:I

    const/4 v0, 0x0

    .line 26
    iput v0, p0, Lwq/g;->m:F

    .line 27
    iput v0, p0, Lwq/g;->n:F

    const/4 v0, 0x0

    .line 28
    iput v0, p0, Lwq/g;->o:I

    .line 29
    iput v0, p0, Lwq/g;->p:I

    .line 30
    sget-object v0, Landroid/graphics/Paint$Style;->FILL_AND_STROKE:Landroid/graphics/Paint$Style;

    iput-object v0, p0, Lwq/g;->q:Landroid/graphics/Paint$Style;

    .line 31
    iget-object v0, p1, Lwq/g;->a:Lwq/m;

    iput-object v0, p0, Lwq/g;->a:Lwq/m;

    .line 32
    iget-object v0, p1, Lwq/g;->b:Lwq/x;

    iput-object v0, p0, Lwq/g;->b:Lwq/x;

    .line 33
    iget-object v0, p1, Lwq/g;->c:Lqq/a;

    iput-object v0, p0, Lwq/g;->c:Lqq/a;

    .line 34
    iget v0, p1, Lwq/g;->k:F

    iput v0, p0, Lwq/g;->k:F

    .line 35
    iget-object v0, p1, Lwq/g;->d:Landroid/content/res/ColorStateList;

    iput-object v0, p0, Lwq/g;->d:Landroid/content/res/ColorStateList;

    .line 36
    iget-object v0, p1, Lwq/g;->e:Landroid/content/res/ColorStateList;

    iput-object v0, p0, Lwq/g;->e:Landroid/content/res/ColorStateList;

    .line 37
    iget-object v0, p1, Lwq/g;->g:Landroid/graphics/PorterDuff$Mode;

    iput-object v0, p0, Lwq/g;->g:Landroid/graphics/PorterDuff$Mode;

    .line 38
    iget-object v0, p1, Lwq/g;->f:Landroid/content/res/ColorStateList;

    iput-object v0, p0, Lwq/g;->f:Landroid/content/res/ColorStateList;

    .line 39
    iget v0, p1, Lwq/g;->l:I

    iput v0, p0, Lwq/g;->l:I

    .line 40
    iget v0, p1, Lwq/g;->i:F

    iput v0, p0, Lwq/g;->i:F

    .line 41
    iget v0, p1, Lwq/g;->p:I

    iput v0, p0, Lwq/g;->p:I

    .line 42
    iget v0, p1, Lwq/g;->j:F

    iput v0, p0, Lwq/g;->j:F

    .line 43
    iget v0, p1, Lwq/g;->m:F

    iput v0, p0, Lwq/g;->m:F

    .line 44
    iget v0, p1, Lwq/g;->n:F

    iput v0, p0, Lwq/g;->n:F

    .line 45
    iget v0, p1, Lwq/g;->o:I

    iput v0, p0, Lwq/g;->o:I

    .line 46
    iget-object v0, p1, Lwq/g;->q:Landroid/graphics/Paint$Style;

    iput-object v0, p0, Lwq/g;->q:Landroid/graphics/Paint$Style;

    .line 47
    iget-object v0, p1, Lwq/g;->h:Landroid/graphics/Rect;

    if-eqz v0, :cond_0

    .line 48
    new-instance v0, Landroid/graphics/Rect;

    iget-object p1, p1, Lwq/g;->h:Landroid/graphics/Rect;

    invoke-direct {v0, p1}, Landroid/graphics/Rect;-><init>(Landroid/graphics/Rect;)V

    iput-object v0, p0, Lwq/g;->h:Landroid/graphics/Rect;

    :cond_0
    return-void
.end method

.method public constructor <init>(Lwq/m;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Landroid/graphics/drawable/Drawable$ConstantState;-><init>()V

    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Lwq/g;->d:Landroid/content/res/ColorStateList;

    .line 3
    iput-object v0, p0, Lwq/g;->e:Landroid/content/res/ColorStateList;

    .line 4
    iput-object v0, p0, Lwq/g;->f:Landroid/content/res/ColorStateList;

    .line 5
    sget-object v1, Landroid/graphics/PorterDuff$Mode;->SRC_IN:Landroid/graphics/PorterDuff$Mode;

    iput-object v1, p0, Lwq/g;->g:Landroid/graphics/PorterDuff$Mode;

    .line 6
    iput-object v0, p0, Lwq/g;->h:Landroid/graphics/Rect;

    const/high16 v1, 0x3f800000    # 1.0f

    .line 7
    iput v1, p0, Lwq/g;->i:F

    .line 8
    iput v1, p0, Lwq/g;->j:F

    const/16 v1, 0xff

    .line 9
    iput v1, p0, Lwq/g;->l:I

    const/4 v1, 0x0

    .line 10
    iput v1, p0, Lwq/g;->m:F

    .line 11
    iput v1, p0, Lwq/g;->n:F

    const/4 v1, 0x0

    .line 12
    iput v1, p0, Lwq/g;->o:I

    .line 13
    iput v1, p0, Lwq/g;->p:I

    .line 14
    sget-object v1, Landroid/graphics/Paint$Style;->FILL_AND_STROKE:Landroid/graphics/Paint$Style;

    iput-object v1, p0, Lwq/g;->q:Landroid/graphics/Paint$Style;

    .line 15
    iput-object p1, p0, Lwq/g;->a:Lwq/m;

    .line 16
    iput-object v0, p0, Lwq/g;->c:Lqq/a;

    return-void
.end method


# virtual methods
.method public final getChangingConfigurations()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public newDrawable()Landroid/graphics/drawable/Drawable;
    .locals 1

    .line 1
    new-instance v0, Lwq/i;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lwq/i;-><init>(Lwq/g;)V

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x1

    .line 7
    iput-boolean p0, v0, Lwq/i;->i:Z

    .line 8
    .line 9
    iput-boolean p0, v0, Lwq/i;->j:Z

    .line 10
    .line 11
    return-object v0
.end method
