.class public final Lq4/b;
.super Landroid/text/style/CharacterStyle;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/text/style/UpdateAppearance;


# instance fields
.field public final d:Le3/l0;

.field public final e:F

.field public final f:Ll2/j1;

.field public final g:Ll2/h0;


# direct methods
.method public constructor <init>(Le3/l0;F)V
    .locals 2

    .line 1
    invoke-direct {p0}, Landroid/text/style/CharacterStyle;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lq4/b;->d:Le3/l0;

    .line 5
    .line 6
    iput p2, p0, Lq4/b;->e:F

    .line 7
    .line 8
    new-instance p1, Ld3/e;

    .line 9
    .line 10
    const-wide v0, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 11
    .line 12
    .line 13
    .line 14
    .line 15
    invoke-direct {p1, v0, v1}, Ld3/e;-><init>(J)V

    .line 16
    .line 17
    .line 18
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    iput-object p1, p0, Lq4/b;->f:Ll2/j1;

    .line 23
    .line 24
    new-instance p1, Lmc/e;

    .line 25
    .line 26
    const/16 p2, 0x18

    .line 27
    .line 28
    invoke-direct {p1, p0, p2}, Lmc/e;-><init>(Ljava/lang/Object;I)V

    .line 29
    .line 30
    .line 31
    invoke-static {p1}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    iput-object p1, p0, Lq4/b;->g:Ll2/h0;

    .line 36
    .line 37
    return-void
.end method


# virtual methods
.method public final updateDrawState(Landroid/text/TextPaint;)V
    .locals 1

    .line 1
    iget v0, p0, Lq4/b;->e:F

    .line 2
    .line 3
    invoke-static {p1, v0}, Lo4/i;->b(Landroid/text/TextPaint;F)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lq4/b;->g:Ll2/h0;

    .line 7
    .line 8
    invoke-virtual {p0}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Landroid/graphics/Shader;

    .line 13
    .line 14
    invoke-virtual {p1, p0}, Landroid/graphics/Paint;->setShader(Landroid/graphics/Shader;)Landroid/graphics/Shader;

    .line 15
    .line 16
    .line 17
    return-void
.end method
