.class public final Lc2/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/inputmethod/InputConnection;


# instance fields
.field public final a:Lbu/c;

.field public final b:Z

.field public final c:Lt1/p0;

.field public final d:Le2/w0;

.field public final e:Lw3/h2;

.field public f:I

.field public g:Ll4/v;

.field public h:I

.field public i:Z

.field public final j:Ljava/util/ArrayList;

.field public k:Z


# direct methods
.method public constructor <init>(Ll4/v;Lbu/c;ZLt1/p0;Le2/w0;Lw3/h2;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lc2/q;->a:Lbu/c;

    .line 5
    .line 6
    iput-boolean p3, p0, Lc2/q;->b:Z

    .line 7
    .line 8
    iput-object p4, p0, Lc2/q;->c:Lt1/p0;

    .line 9
    .line 10
    iput-object p5, p0, Lc2/q;->d:Le2/w0;

    .line 11
    .line 12
    iput-object p6, p0, Lc2/q;->e:Lw3/h2;

    .line 13
    .line 14
    iput-object p1, p0, Lc2/q;->g:Ll4/v;

    .line 15
    .line 16
    new-instance p1, Ljava/util/ArrayList;

    .line 17
    .line 18
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 19
    .line 20
    .line 21
    iput-object p1, p0, Lc2/q;->j:Ljava/util/ArrayList;

    .line 22
    .line 23
    const/4 p1, 0x1

    .line 24
    iput-boolean p1, p0, Lc2/q;->k:Z

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final a(Ll4/g;)V
    .locals 1

    .line 1
    iget v0, p0, Lc2/q;->f:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, 0x1

    .line 4
    .line 5
    iput v0, p0, Lc2/q;->f:I

    .line 6
    .line 7
    :try_start_0
    iget-object v0, p0, Lc2/q;->j:Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0}, Lc2/q;->b()Z

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :catchall_0
    move-exception p1

    .line 17
    invoke-virtual {p0}, Lc2/q;->b()Z

    .line 18
    .line 19
    .line 20
    throw p1
.end method

.method public final b()Z
    .locals 3

    .line 1
    iget v0, p0, Lc2/q;->f:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, -0x1

    .line 4
    .line 5
    iput v0, p0, Lc2/q;->f:I

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iget-object v0, p0, Lc2/q;->j:Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-nez v1, :cond_0

    .line 16
    .line 17
    invoke-static {v0}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    iget-object v2, p0, Lc2/q;->a:Lbu/c;

    .line 22
    .line 23
    iget-object v2, v2, Lbu/c;->e:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v2, Lc2/p;

    .line 26
    .line 27
    iget-object v2, v2, Lc2/p;->c:Lay0/k;

    .line 28
    .line 29
    invoke-interface {v2, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 33
    .line 34
    .line 35
    :cond_0
    iget p0, p0, Lc2/q;->f:I

    .line 36
    .line 37
    if-lez p0, :cond_1

    .line 38
    .line 39
    const/4 p0, 0x1

    .line 40
    return p0

    .line 41
    :cond_1
    const/4 p0, 0x0

    .line 42
    return p0
.end method

.method public final beginBatchEdit()Z
    .locals 2

    .line 1
    iget-boolean v0, p0, Lc2/q;->k:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget v0, p0, Lc2/q;->f:I

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    add-int/2addr v0, v1

    .line 9
    iput v0, p0, Lc2/q;->f:I

    .line 10
    .line 11
    return v1

    .line 12
    :cond_0
    return v0
.end method

.method public final c(I)V
    .locals 2

    .line 1
    new-instance v0, Landroid/view/KeyEvent;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1, p1}, Landroid/view/KeyEvent;-><init>(II)V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0, v0}, Lc2/q;->sendKeyEvent(Landroid/view/KeyEvent;)Z

    .line 8
    .line 9
    .line 10
    new-instance v0, Landroid/view/KeyEvent;

    .line 11
    .line 12
    const/4 v1, 0x1

    .line 13
    invoke-direct {v0, v1, p1}, Landroid/view/KeyEvent;-><init>(II)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0, v0}, Lc2/q;->sendKeyEvent(Landroid/view/KeyEvent;)Z

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public final clearMetaKeyStates(I)Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lc2/q;->k:Z

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    :cond_0
    return p0
.end method

.method public final closeConnection()V
    .locals 4

    .line 1
    iget-object v0, p0, Lc2/q;->j:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    iput v0, p0, Lc2/q;->f:I

    .line 8
    .line 9
    iput-boolean v0, p0, Lc2/q;->k:Z

    .line 10
    .line 11
    iget-object v1, p0, Lc2/q;->a:Lbu/c;

    .line 12
    .line 13
    iget-object v1, v1, Lbu/c;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v1, Lc2/p;

    .line 16
    .line 17
    iget-object v1, v1, Lc2/p;->j:Ljava/util/ArrayList;

    .line 18
    .line 19
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    :goto_0
    if-ge v0, v2, :cond_1

    .line 24
    .line 25
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    check-cast v3, Ljava/lang/ref/WeakReference;

    .line 30
    .line 31
    invoke-virtual {v3}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    invoke-static {v3, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    if-eqz v3, :cond_0

    .line 40
    .line 41
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    return-void

    .line 45
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_1
    return-void
.end method

.method public final commitCompletion(Landroid/view/inputmethod/CompletionInfo;)Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lc2/q;->k:Z

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    :cond_0
    return p0
.end method

.method public final commitContent(Landroid/view/inputmethod/InputContentInfo;ILandroid/os/Bundle;)Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lc2/q;->k:Z

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    :cond_0
    return p0
.end method

.method public final commitCorrection(Landroid/view/inputmethod/CorrectionInfo;)Z
    .locals 0

    .line 1
    iget-boolean p1, p0, Lc2/q;->k:Z

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    iget-boolean p0, p0, Lc2/q;->b:Z

    .line 6
    .line 7
    return p0

    .line 8
    :cond_0
    return p1
.end method

.method public final commitText(Ljava/lang/CharSequence;I)Z
    .locals 2

    .line 1
    iget-boolean v0, p0, Lc2/q;->k:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    new-instance v1, Ll4/a;

    .line 6
    .line 7
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    invoke-direct {v1, p1, p2}, Ll4/a;-><init>(Ljava/lang/String;I)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0, v1}, Lc2/q;->a(Ll4/g;)V

    .line 15
    .line 16
    .line 17
    :cond_0
    return v0
.end method

.method public final deleteSurroundingText(II)Z
    .locals 1

    .line 1
    iget-boolean v0, p0, Lc2/q;->k:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Ll4/e;

    .line 6
    .line 7
    invoke-direct {v0, p1, p2}, Ll4/e;-><init>(II)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, v0}, Lc2/q;->a(Ll4/g;)V

    .line 11
    .line 12
    .line 13
    const/4 p0, 0x1

    .line 14
    return p0

    .line 15
    :cond_0
    return v0
.end method

.method public final deleteSurroundingTextInCodePoints(II)Z
    .locals 1

    .line 1
    iget-boolean v0, p0, Lc2/q;->k:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Ll4/f;

    .line 6
    .line 7
    invoke-direct {v0, p1, p2}, Ll4/f;-><init>(II)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, v0}, Lc2/q;->a(Ll4/g;)V

    .line 11
    .line 12
    .line 13
    const/4 p0, 0x1

    .line 14
    return p0

    .line 15
    :cond_0
    return v0
.end method

.method public final endBatchEdit()Z
    .locals 0

    .line 1
    invoke-virtual {p0}, Lc2/q;->b()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final finishComposingText()Z
    .locals 1

    .line 1
    iget-boolean v0, p0, Lc2/q;->k:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Ll4/h;

    .line 6
    .line 7
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, v0}, Lc2/q;->a(Ll4/g;)V

    .line 11
    .line 12
    .line 13
    const/4 p0, 0x1

    .line 14
    return p0

    .line 15
    :cond_0
    return v0
.end method

.method public final getCursorCapsMode(I)I
    .locals 3

    .line 1
    iget-object p0, p0, Lc2/q;->g:Ll4/v;

    .line 2
    .line 3
    iget-object v0, p0, Ll4/v;->a:Lg4/g;

    .line 4
    .line 5
    iget-object v0, v0, Lg4/g;->e:Ljava/lang/String;

    .line 6
    .line 7
    iget-wide v1, p0, Ll4/v;->b:J

    .line 8
    .line 9
    invoke-static {v1, v2}, Lg4/o0;->f(J)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    invoke-static {v0, p0, p1}, Landroid/text/TextUtils;->getCapsMode(Ljava/lang/CharSequence;II)I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0
.end method

.method public final getExtractedText(Landroid/view/inputmethod/ExtractedTextRequest;I)Landroid/view/inputmethod/ExtractedText;
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    and-int/2addr p2, v0

    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz p2, :cond_0

    .line 5
    .line 6
    goto :goto_0

    .line 7
    :cond_0
    move v0, v1

    .line 8
    :goto_0
    iput-boolean v0, p0, Lc2/q;->i:Z

    .line 9
    .line 10
    if-eqz v0, :cond_2

    .line 11
    .line 12
    if-eqz p1, :cond_1

    .line 13
    .line 14
    iget v1, p1, Landroid/view/inputmethod/ExtractedTextRequest;->token:I

    .line 15
    .line 16
    :cond_1
    iput v1, p0, Lc2/q;->h:I

    .line 17
    .line 18
    :cond_2
    iget-object p0, p0, Lc2/q;->g:Ll4/v;

    .line 19
    .line 20
    invoke-static {p0}, Ljp/pc;->a(Ll4/v;)Landroid/view/inputmethod/ExtractedText;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method

.method public final getHandler()Landroid/os/Handler;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public final getSelectedText(I)Ljava/lang/CharSequence;
    .locals 2

    .line 1
    iget-object p1, p0, Lc2/q;->g:Ll4/v;

    .line 2
    .line 3
    iget-wide v0, p1, Ll4/v;->b:J

    .line 4
    .line 5
    invoke-static {v0, v1}, Lg4/o0;->c(J)Z

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    if-eqz p1, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    return-object p0

    .line 13
    :cond_0
    iget-object p0, p0, Lc2/q;->g:Ll4/v;

    .line 14
    .line 15
    invoke-static {p0}, Llp/re;->b(Ll4/v;)Lg4/g;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    iget-object p0, p0, Lg4/g;->e:Ljava/lang/String;

    .line 20
    .line 21
    return-object p0
.end method

.method public final getTextAfterCursor(II)Ljava/lang/CharSequence;
    .locals 0

    .line 1
    iget-object p0, p0, Lc2/q;->g:Ll4/v;

    .line 2
    .line 3
    invoke-static {p0, p1}, Llp/re;->c(Ll4/v;I)Lg4/g;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iget-object p0, p0, Lg4/g;->e:Ljava/lang/String;

    .line 8
    .line 9
    return-object p0
.end method

.method public final getTextBeforeCursor(II)Ljava/lang/CharSequence;
    .locals 0

    .line 1
    iget-object p0, p0, Lc2/q;->g:Ll4/v;

    .line 2
    .line 3
    invoke-static {p0, p1}, Llp/re;->d(Ll4/v;I)Lg4/g;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iget-object p0, p0, Lg4/g;->e:Ljava/lang/String;

    .line 8
    .line 9
    return-object p0
.end method

.method public final performContextMenuAction(I)Z
    .locals 2

    .line 1
    iget-boolean v0, p0, Lc2/q;->k:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    packed-switch p1, :pswitch_data_0

    .line 7
    .line 8
    .line 9
    return v0

    .line 10
    :pswitch_0
    const/16 p1, 0x117

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Lc2/q;->c(I)V

    .line 13
    .line 14
    .line 15
    return v0

    .line 16
    :pswitch_1
    const/16 p1, 0x116

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lc2/q;->c(I)V

    .line 19
    .line 20
    .line 21
    return v0

    .line 22
    :pswitch_2
    const/16 p1, 0x115

    .line 23
    .line 24
    invoke-virtual {p0, p1}, Lc2/q;->c(I)V

    .line 25
    .line 26
    .line 27
    return v0

    .line 28
    :pswitch_3
    new-instance p1, Ll4/u;

    .line 29
    .line 30
    iget-object v1, p0, Lc2/q;->g:Ll4/v;

    .line 31
    .line 32
    iget-object v1, v1, Ll4/v;->a:Lg4/g;

    .line 33
    .line 34
    iget-object v1, v1, Lg4/g;->e:Ljava/lang/String;

    .line 35
    .line 36
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    invoke-direct {p1, v0, v1}, Ll4/u;-><init>(II)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p0, p1}, Lc2/q;->a(Ll4/g;)V

    .line 44
    .line 45
    .line 46
    :cond_0
    return v0

    .line 47
    :pswitch_data_0
    .packed-switch 0x102001f
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final performEditorAction(I)Z
    .locals 3

    .line 1
    iget-boolean v0, p0, Lc2/q;->k:Z

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    if-eqz p1, :cond_0

    .line 7
    .line 8
    packed-switch p1, :pswitch_data_0

    .line 9
    .line 10
    .line 11
    new-instance v1, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const-string v2, "IME sends unsupported Editor Action: "

    .line 14
    .line 15
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    const-string v1, "RecordingIC"

    .line 26
    .line 27
    invoke-static {v1, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 28
    .line 29
    .line 30
    :cond_0
    move p1, v0

    .line 31
    goto :goto_0

    .line 32
    :pswitch_0
    const/4 p1, 0x5

    .line 33
    goto :goto_0

    .line 34
    :pswitch_1
    const/4 p1, 0x7

    .line 35
    goto :goto_0

    .line 36
    :pswitch_2
    const/4 p1, 0x6

    .line 37
    goto :goto_0

    .line 38
    :pswitch_3
    const/4 p1, 0x4

    .line 39
    goto :goto_0

    .line 40
    :pswitch_4
    const/4 p1, 0x3

    .line 41
    goto :goto_0

    .line 42
    :pswitch_5
    const/4 p1, 0x2

    .line 43
    :goto_0
    iget-object p0, p0, Lc2/q;->a:Lbu/c;

    .line 44
    .line 45
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast p0, Lc2/p;

    .line 48
    .line 49
    iget-object p0, p0, Lc2/p;->d:Lay0/k;

    .line 50
    .line 51
    new-instance v1, Ll4/i;

    .line 52
    .line 53
    invoke-direct {v1, p1}, Ll4/i;-><init>(I)V

    .line 54
    .line 55
    .line 56
    invoke-interface {p0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    :cond_1
    return v0

    .line 60
    nop

    .line 61
    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final performHandwritingGesture(Landroid/view/inputmethod/HandwritingGesture;Ljava/util/concurrent/Executor;Ljava/util/function/IntConsumer;)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    move-object/from16 v2, p3

    .line 6
    .line 7
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 8
    .line 9
    const/16 v4, 0x22

    .line 10
    .line 11
    if-lt v3, v4, :cond_31

    .line 12
    .line 13
    new-instance v3, La2/e;

    .line 14
    .line 15
    const/16 v4, 0x8

    .line 16
    .line 17
    invoke-direct {v3, v0, v4}, La2/e;-><init>(Ljava/lang/Object;I)V

    .line 18
    .line 19
    .line 20
    const/4 v4, 0x1

    .line 21
    iget-object v5, v0, Lc2/q;->c:Lt1/p0;

    .line 22
    .line 23
    const/4 v6, 0x3

    .line 24
    if-eqz v5, :cond_2e

    .line 25
    .line 26
    iget-object v7, v5, Lt1/p0;->j:Lg4/g;

    .line 27
    .line 28
    if-nez v7, :cond_0

    .line 29
    .line 30
    goto/16 :goto_12

    .line 31
    .line 32
    :cond_0
    invoke-virtual {v5}, Lt1/p0;->d()Lt1/j1;

    .line 33
    .line 34
    .line 35
    move-result-object v8

    .line 36
    const/4 v9, 0x0

    .line 37
    if-eqz v8, :cond_1

    .line 38
    .line 39
    iget-object v8, v8, Lt1/j1;->a:Lg4/l0;

    .line 40
    .line 41
    iget-object v8, v8, Lg4/l0;->a:Lg4/k0;

    .line 42
    .line 43
    if-eqz v8, :cond_1

    .line 44
    .line 45
    iget-object v8, v8, Lg4/k0;->a:Lg4/g;

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_1
    move-object v8, v9

    .line 49
    :goto_0
    invoke-virtual {v7, v8}, Lg4/g;->equals(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v8

    .line 53
    if-nez v8, :cond_2

    .line 54
    .line 55
    goto/16 :goto_12

    .line 56
    .line 57
    :cond_2
    invoke-static/range {p1 .. p1}, Lc2/f;->t(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v6

    .line 61
    const-wide v10, 0xffffffffL

    .line 62
    .line 63
    .line 64
    .line 65
    .line 66
    const/4 v8, 0x0

    .line 67
    const/16 v12, 0x20

    .line 68
    .line 69
    iget-object v13, v0, Lc2/q;->d:Le2/w0;

    .line 70
    .line 71
    if-eqz v6, :cond_6

    .line 72
    .line 73
    invoke-static/range {p1 .. p1}, Lc2/f;->n(Ljava/lang/Object;)Landroid/view/inputmethod/SelectGesture;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    invoke-static {v0}, Lc2/f;->i(Landroid/view/inputmethod/SelectGesture;)Landroid/graphics/RectF;

    .line 78
    .line 79
    .line 80
    move-result-object v6

    .line 81
    invoke-static {v6}, Le3/j0;->C(Landroid/graphics/RectF;)Ld3/c;

    .line 82
    .line 83
    .line 84
    move-result-object v6

    .line 85
    invoke-static {v0}, Lc2/f;->c(Landroid/view/inputmethod/SelectGesture;)I

    .line 86
    .line 87
    .line 88
    move-result v7

    .line 89
    if-eq v7, v4, :cond_3

    .line 90
    .line 91
    goto :goto_1

    .line 92
    :cond_3
    move v8, v4

    .line 93
    :goto_1
    invoke-static {v5, v6, v8}, Ljp/ic;->g(Lt1/p0;Ld3/c;I)J

    .line 94
    .line 95
    .line 96
    move-result-wide v5

    .line 97
    invoke-static {v5, v6}, Lg4/o0;->c(J)Z

    .line 98
    .line 99
    .line 100
    move-result v7

    .line 101
    if-eqz v7, :cond_4

    .line 102
    .line 103
    invoke-static {v0}, Lc2/f;->j(Ljava/lang/Object;)Landroid/view/inputmethod/HandwritingGesture;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    invoke-static {v0, v3}, Ljp/hc;->a(Landroid/view/inputmethod/HandwritingGesture;La2/e;)I

    .line 108
    .line 109
    .line 110
    move-result v6

    .line 111
    goto/16 :goto_12

    .line 112
    .line 113
    :cond_4
    new-instance v0, Ll4/u;

    .line 114
    .line 115
    shr-long v7, v5, v12

    .line 116
    .line 117
    long-to-int v7, v7

    .line 118
    and-long/2addr v5, v10

    .line 119
    long-to-int v5, v5

    .line 120
    invoke-direct {v0, v7, v5}, Ll4/u;-><init>(II)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {v3, v0}, La2/e;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    if-eqz v13, :cond_5

    .line 127
    .line 128
    invoke-virtual {v13, v4}, Le2/w0;->h(Z)V

    .line 129
    .line 130
    .line 131
    :cond_5
    :goto_2
    move v6, v4

    .line 132
    goto/16 :goto_12

    .line 133
    .line 134
    :cond_6
    invoke-static/range {p1 .. p1}, Lc2/h;->y(Ljava/lang/Object;)Z

    .line 135
    .line 136
    .line 137
    move-result v6

    .line 138
    if-eqz v6, :cond_a

    .line 139
    .line 140
    invoke-static/range {p1 .. p1}, Lc2/h;->m(Ljava/lang/Object;)Landroid/view/inputmethod/DeleteGesture;

    .line 141
    .line 142
    .line 143
    move-result-object v0

    .line 144
    invoke-static {v0}, Lc2/f;->a(Landroid/view/inputmethod/DeleteGesture;)I

    .line 145
    .line 146
    .line 147
    move-result v6

    .line 148
    if-eq v6, v4, :cond_7

    .line 149
    .line 150
    move v6, v8

    .line 151
    goto :goto_3

    .line 152
    :cond_7
    move v6, v4

    .line 153
    :goto_3
    invoke-static {v0}, Lc2/f;->g(Landroid/view/inputmethod/DeleteGesture;)Landroid/graphics/RectF;

    .line 154
    .line 155
    .line 156
    move-result-object v9

    .line 157
    invoke-static {v9}, Le3/j0;->C(Landroid/graphics/RectF;)Ld3/c;

    .line 158
    .line 159
    .line 160
    move-result-object v9

    .line 161
    invoke-static {v5, v9, v6}, Ljp/ic;->g(Lt1/p0;Ld3/c;I)J

    .line 162
    .line 163
    .line 164
    move-result-wide v9

    .line 165
    invoke-static {v9, v10}, Lg4/o0;->c(J)Z

    .line 166
    .line 167
    .line 168
    move-result v5

    .line 169
    if-eqz v5, :cond_8

    .line 170
    .line 171
    invoke-static {v0}, Lc2/f;->j(Ljava/lang/Object;)Landroid/view/inputmethod/HandwritingGesture;

    .line 172
    .line 173
    .line 174
    move-result-object v0

    .line 175
    invoke-static {v0, v3}, Ljp/hc;->a(Landroid/view/inputmethod/HandwritingGesture;La2/e;)I

    .line 176
    .line 177
    .line 178
    move-result v6

    .line 179
    goto/16 :goto_12

    .line 180
    .line 181
    :cond_8
    if-ne v6, v4, :cond_9

    .line 182
    .line 183
    move v8, v4

    .line 184
    :cond_9
    invoke-static {v9, v10, v7, v8, v3}, Ljp/hc;->c(JLg4/g;ZLa2/e;)V

    .line 185
    .line 186
    .line 187
    goto :goto_2

    .line 188
    :cond_a
    invoke-static/range {p1 .. p1}, Lc2/h;->C(Ljava/lang/Object;)Z

    .line 189
    .line 190
    .line 191
    move-result v6

    .line 192
    if-eqz v6, :cond_d

    .line 193
    .line 194
    invoke-static/range {p1 .. p1}, Lc2/h;->o(Ljava/lang/Object;)Landroid/view/inputmethod/SelectRangeGesture;

    .line 195
    .line 196
    .line 197
    move-result-object v0

    .line 198
    invoke-static {v0}, Lc2/h;->j(Landroid/view/inputmethod/SelectRangeGesture;)Landroid/graphics/RectF;

    .line 199
    .line 200
    .line 201
    move-result-object v6

    .line 202
    invoke-static {v6}, Le3/j0;->C(Landroid/graphics/RectF;)Ld3/c;

    .line 203
    .line 204
    .line 205
    move-result-object v6

    .line 206
    invoke-static {v0}, Lc2/h;->B(Landroid/view/inputmethod/SelectRangeGesture;)Landroid/graphics/RectF;

    .line 207
    .line 208
    .line 209
    move-result-object v7

    .line 210
    invoke-static {v7}, Le3/j0;->C(Landroid/graphics/RectF;)Ld3/c;

    .line 211
    .line 212
    .line 213
    move-result-object v7

    .line 214
    invoke-static {v0}, Lc2/f;->d(Landroid/view/inputmethod/SelectRangeGesture;)I

    .line 215
    .line 216
    .line 217
    move-result v9

    .line 218
    if-eq v9, v4, :cond_b

    .line 219
    .line 220
    goto :goto_4

    .line 221
    :cond_b
    move v8, v4

    .line 222
    :goto_4
    invoke-static {v5, v6, v7, v8}, Ljp/ic;->b(Lt1/p0;Ld3/c;Ld3/c;I)J

    .line 223
    .line 224
    .line 225
    move-result-wide v5

    .line 226
    invoke-static {v5, v6}, Lg4/o0;->c(J)Z

    .line 227
    .line 228
    .line 229
    move-result v7

    .line 230
    if-eqz v7, :cond_c

    .line 231
    .line 232
    invoke-static {v0}, Lc2/f;->j(Ljava/lang/Object;)Landroid/view/inputmethod/HandwritingGesture;

    .line 233
    .line 234
    .line 235
    move-result-object v0

    .line 236
    invoke-static {v0, v3}, Ljp/hc;->a(Landroid/view/inputmethod/HandwritingGesture;La2/e;)I

    .line 237
    .line 238
    .line 239
    move-result v6

    .line 240
    goto/16 :goto_12

    .line 241
    .line 242
    :cond_c
    new-instance v0, Ll4/u;

    .line 243
    .line 244
    shr-long v7, v5, v12

    .line 245
    .line 246
    long-to-int v7, v7

    .line 247
    and-long/2addr v5, v10

    .line 248
    long-to-int v5, v5

    .line 249
    invoke-direct {v0, v7, v5}, Ll4/u;-><init>(II)V

    .line 250
    .line 251
    .line 252
    invoke-virtual {v3, v0}, La2/e;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 253
    .line 254
    .line 255
    if-eqz v13, :cond_5

    .line 256
    .line 257
    invoke-virtual {v13, v4}, Le2/w0;->h(Z)V

    .line 258
    .line 259
    .line 260
    goto/16 :goto_2

    .line 261
    .line 262
    :cond_d
    invoke-static/range {p1 .. p1}, Lc2/h;->D(Ljava/lang/Object;)Z

    .line 263
    .line 264
    .line 265
    move-result v6

    .line 266
    if-eqz v6, :cond_11

    .line 267
    .line 268
    invoke-static/range {p1 .. p1}, Lc2/h;->n(Ljava/lang/Object;)Landroid/view/inputmethod/DeleteRangeGesture;

    .line 269
    .line 270
    .line 271
    move-result-object v0

    .line 272
    invoke-static {v0}, Lc2/f;->b(Landroid/view/inputmethod/DeleteRangeGesture;)I

    .line 273
    .line 274
    .line 275
    move-result v6

    .line 276
    if-eq v6, v4, :cond_e

    .line 277
    .line 278
    move v6, v8

    .line 279
    goto :goto_5

    .line 280
    :cond_e
    move v6, v4

    .line 281
    :goto_5
    invoke-static {v0}, Lc2/f;->h(Landroid/view/inputmethod/DeleteRangeGesture;)Landroid/graphics/RectF;

    .line 282
    .line 283
    .line 284
    move-result-object v9

    .line 285
    invoke-static {v9}, Le3/j0;->C(Landroid/graphics/RectF;)Ld3/c;

    .line 286
    .line 287
    .line 288
    move-result-object v9

    .line 289
    invoke-static {v0}, Lc2/f;->u(Landroid/view/inputmethod/DeleteRangeGesture;)Landroid/graphics/RectF;

    .line 290
    .line 291
    .line 292
    move-result-object v10

    .line 293
    invoke-static {v10}, Le3/j0;->C(Landroid/graphics/RectF;)Ld3/c;

    .line 294
    .line 295
    .line 296
    move-result-object v10

    .line 297
    invoke-static {v5, v9, v10, v6}, Ljp/ic;->b(Lt1/p0;Ld3/c;Ld3/c;I)J

    .line 298
    .line 299
    .line 300
    move-result-wide v9

    .line 301
    invoke-static {v9, v10}, Lg4/o0;->c(J)Z

    .line 302
    .line 303
    .line 304
    move-result v5

    .line 305
    if-eqz v5, :cond_f

    .line 306
    .line 307
    invoke-static {v0}, Lc2/f;->j(Ljava/lang/Object;)Landroid/view/inputmethod/HandwritingGesture;

    .line 308
    .line 309
    .line 310
    move-result-object v0

    .line 311
    invoke-static {v0, v3}, Ljp/hc;->a(Landroid/view/inputmethod/HandwritingGesture;La2/e;)I

    .line 312
    .line 313
    .line 314
    move-result v6

    .line 315
    goto/16 :goto_12

    .line 316
    .line 317
    :cond_f
    if-ne v6, v4, :cond_10

    .line 318
    .line 319
    move v8, v4

    .line 320
    :cond_10
    invoke-static {v9, v10, v7, v8, v3}, Ljp/hc;->c(JLg4/g;ZLa2/e;)V

    .line 321
    .line 322
    .line 323
    goto/16 :goto_2

    .line 324
    .line 325
    :cond_11
    invoke-static/range {p1 .. p1}, Lc2/f;->A(Ljava/lang/Object;)Z

    .line 326
    .line 327
    .line 328
    move-result v6

    .line 329
    const/4 v10, 0x2

    .line 330
    iget-object v0, v0, Lc2/q;->e:Lw3/h2;

    .line 331
    .line 332
    const/4 v11, -0x1

    .line 333
    if-eqz v6, :cond_1a

    .line 334
    .line 335
    invoke-static/range {p1 .. p1}, Lc2/f;->l(Ljava/lang/Object;)Landroid/view/inputmethod/JoinOrSplitGesture;

    .line 336
    .line 337
    .line 338
    move-result-object v6

    .line 339
    if-nez v0, :cond_12

    .line 340
    .line 341
    invoke-static {v6}, Lc2/f;->j(Ljava/lang/Object;)Landroid/view/inputmethod/HandwritingGesture;

    .line 342
    .line 343
    .line 344
    move-result-object v0

    .line 345
    invoke-static {v0, v3}, Ljp/hc;->a(Landroid/view/inputmethod/HandwritingGesture;La2/e;)I

    .line 346
    .line 347
    .line 348
    move-result v6

    .line 349
    goto/16 :goto_12

    .line 350
    .line 351
    :cond_12
    invoke-static {v6}, Lc2/h;->h(Landroid/view/inputmethod/JoinOrSplitGesture;)Landroid/graphics/PointF;

    .line 352
    .line 353
    .line 354
    move-result-object v9

    .line 355
    invoke-static {v9}, Ljp/ic;->d(Landroid/graphics/PointF;)J

    .line 356
    .line 357
    .line 358
    move-result-wide v13

    .line 359
    invoke-static {v5, v13, v14, v0}, Ljp/ic;->a(Lt1/p0;JLw3/h2;)I

    .line 360
    .line 361
    .line 362
    move-result v0

    .line 363
    if-eq v0, v11, :cond_19

    .line 364
    .line 365
    invoke-virtual {v5}, Lt1/p0;->d()Lt1/j1;

    .line 366
    .line 367
    .line 368
    move-result-object v5

    .line 369
    if-eqz v5, :cond_13

    .line 370
    .line 371
    iget-object v5, v5, Lt1/j1;->a:Lg4/l0;

    .line 372
    .line 373
    invoke-static {v5, v0}, Ljp/ic;->c(Lg4/l0;I)Z

    .line 374
    .line 375
    .line 376
    move-result v5

    .line 377
    if-ne v5, v4, :cond_13

    .line 378
    .line 379
    goto :goto_9

    .line 380
    :cond_13
    move v5, v0

    .line 381
    :goto_6
    if-lez v5, :cond_15

    .line 382
    .line 383
    invoke-static {v7, v5}, Ljava/lang/Character;->codePointBefore(Ljava/lang/CharSequence;I)I

    .line 384
    .line 385
    .line 386
    move-result v6

    .line 387
    invoke-static {v6}, Ljp/ic;->i(I)Z

    .line 388
    .line 389
    .line 390
    move-result v9

    .line 391
    if-nez v9, :cond_14

    .line 392
    .line 393
    goto :goto_7

    .line 394
    :cond_14
    invoke-static {v6}, Ljava/lang/Character;->charCount(I)I

    .line 395
    .line 396
    .line 397
    move-result v6

    .line 398
    sub-int/2addr v5, v6

    .line 399
    goto :goto_6

    .line 400
    :cond_15
    :goto_7
    iget-object v6, v7, Lg4/g;->e:Ljava/lang/String;

    .line 401
    .line 402
    invoke-virtual {v6}, Ljava/lang/String;->length()I

    .line 403
    .line 404
    .line 405
    move-result v6

    .line 406
    if-ge v0, v6, :cond_17

    .line 407
    .line 408
    invoke-static {v7, v0}, Ljava/lang/Character;->codePointAt(Ljava/lang/CharSequence;I)I

    .line 409
    .line 410
    .line 411
    move-result v6

    .line 412
    invoke-static {v6}, Ljp/ic;->i(I)Z

    .line 413
    .line 414
    .line 415
    move-result v9

    .line 416
    if-nez v9, :cond_16

    .line 417
    .line 418
    goto :goto_8

    .line 419
    :cond_16
    invoke-static {v6}, Ljava/lang/Character;->charCount(I)I

    .line 420
    .line 421
    .line 422
    move-result v6

    .line 423
    add-int/2addr v0, v6

    .line 424
    goto :goto_7

    .line 425
    :cond_17
    :goto_8
    invoke-static {v5, v0}, Lg4/f0;->b(II)J

    .line 426
    .line 427
    .line 428
    move-result-wide v5

    .line 429
    invoke-static {v5, v6}, Lg4/o0;->c(J)Z

    .line 430
    .line 431
    .line 432
    move-result v0

    .line 433
    if-eqz v0, :cond_18

    .line 434
    .line 435
    shr-long/2addr v5, v12

    .line 436
    long-to-int v0, v5

    .line 437
    new-instance v5, Ll4/u;

    .line 438
    .line 439
    invoke-direct {v5, v0, v0}, Ll4/u;-><init>(II)V

    .line 440
    .line 441
    .line 442
    new-instance v0, Ll4/a;

    .line 443
    .line 444
    const-string v6, " "

    .line 445
    .line 446
    invoke-direct {v0, v6, v4}, Ll4/a;-><init>(Ljava/lang/String;I)V

    .line 447
    .line 448
    .line 449
    new-array v6, v10, [Ll4/g;

    .line 450
    .line 451
    aput-object v5, v6, v8

    .line 452
    .line 453
    aput-object v0, v6, v4

    .line 454
    .line 455
    new-instance v0, Lc2/j;

    .line 456
    .line 457
    invoke-direct {v0, v6}, Lc2/j;-><init>([Ll4/g;)V

    .line 458
    .line 459
    .line 460
    invoke-virtual {v3, v0}, La2/e;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 461
    .line 462
    .line 463
    goto/16 :goto_2

    .line 464
    .line 465
    :cond_18
    invoke-static {v5, v6, v7, v8, v3}, Ljp/hc;->c(JLg4/g;ZLa2/e;)V

    .line 466
    .line 467
    .line 468
    goto/16 :goto_2

    .line 469
    .line 470
    :cond_19
    :goto_9
    invoke-static {v6}, Lc2/f;->j(Ljava/lang/Object;)Landroid/view/inputmethod/HandwritingGesture;

    .line 471
    .line 472
    .line 473
    move-result-object v0

    .line 474
    invoke-static {v0, v3}, Ljp/hc;->a(Landroid/view/inputmethod/HandwritingGesture;La2/e;)I

    .line 475
    .line 476
    .line 477
    move-result v6

    .line 478
    goto/16 :goto_12

    .line 479
    .line 480
    :cond_1a
    invoke-static/range {p1 .. p1}, Lc2/f;->w(Ljava/lang/Object;)Z

    .line 481
    .line 482
    .line 483
    move-result v6

    .line 484
    if-eqz v6, :cond_1e

    .line 485
    .line 486
    invoke-static/range {p1 .. p1}, Lc2/f;->k(Ljava/lang/Object;)Landroid/view/inputmethod/InsertGesture;

    .line 487
    .line 488
    .line 489
    move-result-object v6

    .line 490
    if-nez v0, :cond_1b

    .line 491
    .line 492
    invoke-static {v6}, Lc2/f;->j(Ljava/lang/Object;)Landroid/view/inputmethod/HandwritingGesture;

    .line 493
    .line 494
    .line 495
    move-result-object v0

    .line 496
    invoke-static {v0, v3}, Ljp/hc;->a(Landroid/view/inputmethod/HandwritingGesture;La2/e;)I

    .line 497
    .line 498
    .line 499
    move-result v6

    .line 500
    goto/16 :goto_12

    .line 501
    .line 502
    :cond_1b
    invoke-static {v6}, Lc2/f;->e(Landroid/view/inputmethod/InsertGesture;)Landroid/graphics/PointF;

    .line 503
    .line 504
    .line 505
    move-result-object v7

    .line 506
    invoke-static {v7}, Ljp/ic;->d(Landroid/graphics/PointF;)J

    .line 507
    .line 508
    .line 509
    move-result-wide v12

    .line 510
    invoke-static {v5, v12, v13, v0}, Ljp/ic;->a(Lt1/p0;JLw3/h2;)I

    .line 511
    .line 512
    .line 513
    move-result v0

    .line 514
    if-eq v0, v11, :cond_1d

    .line 515
    .line 516
    invoke-virtual {v5}, Lt1/p0;->d()Lt1/j1;

    .line 517
    .line 518
    .line 519
    move-result-object v5

    .line 520
    if-eqz v5, :cond_1c

    .line 521
    .line 522
    iget-object v5, v5, Lt1/j1;->a:Lg4/l0;

    .line 523
    .line 524
    invoke-static {v5, v0}, Ljp/ic;->c(Lg4/l0;I)Z

    .line 525
    .line 526
    .line 527
    move-result v5

    .line 528
    if-ne v5, v4, :cond_1c

    .line 529
    .line 530
    goto :goto_a

    .line 531
    :cond_1c
    invoke-static {v6}, Lc2/f;->p(Landroid/view/inputmethod/InsertGesture;)Ljava/lang/String;

    .line 532
    .line 533
    .line 534
    move-result-object v5

    .line 535
    new-instance v6, Ll4/u;

    .line 536
    .line 537
    invoke-direct {v6, v0, v0}, Ll4/u;-><init>(II)V

    .line 538
    .line 539
    .line 540
    new-instance v0, Ll4/a;

    .line 541
    .line 542
    invoke-direct {v0, v5, v4}, Ll4/a;-><init>(Ljava/lang/String;I)V

    .line 543
    .line 544
    .line 545
    new-array v5, v10, [Ll4/g;

    .line 546
    .line 547
    aput-object v6, v5, v8

    .line 548
    .line 549
    aput-object v0, v5, v4

    .line 550
    .line 551
    new-instance v0, Lc2/j;

    .line 552
    .line 553
    invoke-direct {v0, v5}, Lc2/j;-><init>([Ll4/g;)V

    .line 554
    .line 555
    .line 556
    invoke-virtual {v3, v0}, La2/e;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 557
    .line 558
    .line 559
    goto/16 :goto_2

    .line 560
    .line 561
    :cond_1d
    :goto_a
    invoke-static {v6}, Lc2/f;->j(Ljava/lang/Object;)Landroid/view/inputmethod/HandwritingGesture;

    .line 562
    .line 563
    .line 564
    move-result-object v0

    .line 565
    invoke-static {v0, v3}, Ljp/hc;->a(Landroid/view/inputmethod/HandwritingGesture;La2/e;)I

    .line 566
    .line 567
    .line 568
    move-result v6

    .line 569
    goto/16 :goto_12

    .line 570
    .line 571
    :cond_1e
    invoke-static/range {p1 .. p1}, Lc2/f;->y(Ljava/lang/Object;)Z

    .line 572
    .line 573
    .line 574
    move-result v6

    .line 575
    if-eqz v6, :cond_2d

    .line 576
    .line 577
    invoke-static/range {p1 .. p1}, Lc2/f;->m(Ljava/lang/Object;)Landroid/view/inputmethod/RemoveSpaceGesture;

    .line 578
    .line 579
    .line 580
    move-result-object v6

    .line 581
    invoke-virtual {v5}, Lt1/p0;->d()Lt1/j1;

    .line 582
    .line 583
    .line 584
    move-result-object v13

    .line 585
    if-eqz v13, :cond_1f

    .line 586
    .line 587
    iget-object v9, v13, Lt1/j1;->a:Lg4/l0;

    .line 588
    .line 589
    :cond_1f
    invoke-static {v6}, Lc2/f;->f(Landroid/view/inputmethod/RemoveSpaceGesture;)Landroid/graphics/PointF;

    .line 590
    .line 591
    .line 592
    move-result-object v13

    .line 593
    invoke-static {v13}, Ljp/ic;->d(Landroid/graphics/PointF;)J

    .line 594
    .line 595
    .line 596
    move-result-wide v13

    .line 597
    invoke-static {v6}, Lc2/h;->i(Landroid/view/inputmethod/RemoveSpaceGesture;)Landroid/graphics/PointF;

    .line 598
    .line 599
    .line 600
    move-result-object v15

    .line 601
    move/from16 v16, v4

    .line 602
    .line 603
    move-object/from16 v17, v5

    .line 604
    .line 605
    invoke-static {v15}, Ljp/ic;->d(Landroid/graphics/PointF;)J

    .line 606
    .line 607
    .line 608
    move-result-wide v4

    .line 609
    invoke-virtual/range {v17 .. v17}, Lt1/p0;->c()Lt3/y;

    .line 610
    .line 611
    .line 612
    move-result-object v15

    .line 613
    if-eqz v9, :cond_20

    .line 614
    .line 615
    iget-object v9, v9, Lg4/l0;->b:Lg4/o;

    .line 616
    .line 617
    if-nez v15, :cond_21

    .line 618
    .line 619
    :cond_20
    move/from16 v17, v12

    .line 620
    .line 621
    goto :goto_c

    .line 622
    :cond_21
    invoke-interface {v15, v13, v14}, Lt3/y;->z(J)J

    .line 623
    .line 624
    .line 625
    move-result-wide v13

    .line 626
    invoke-interface {v15, v4, v5}, Lt3/y;->z(J)J

    .line 627
    .line 628
    .line 629
    move-result-wide v4

    .line 630
    invoke-static {v9, v13, v14, v0}, Ljp/ic;->f(Lg4/o;JLw3/h2;)I

    .line 631
    .line 632
    .line 633
    move-result v15

    .line 634
    invoke-static {v9, v4, v5, v0}, Ljp/ic;->f(Lg4/o;JLw3/h2;)I

    .line 635
    .line 636
    .line 637
    move-result v0

    .line 638
    if-ne v15, v11, :cond_22

    .line 639
    .line 640
    if-ne v0, v11, :cond_24

    .line 641
    .line 642
    sget-wide v4, Lg4/o0;->b:J

    .line 643
    .line 644
    move/from16 v17, v12

    .line 645
    .line 646
    goto :goto_d

    .line 647
    :cond_22
    if-ne v0, v11, :cond_23

    .line 648
    .line 649
    goto :goto_b

    .line 650
    :cond_23
    invoke-static {v15, v0}, Ljava/lang/Math;->min(II)I

    .line 651
    .line 652
    .line 653
    move-result v15

    .line 654
    :goto_b
    move v0, v15

    .line 655
    :cond_24
    invoke-virtual {v9, v0}, Lg4/o;->f(I)F

    .line 656
    .line 657
    .line 658
    move-result v15

    .line 659
    invoke-virtual {v9, v0}, Lg4/o;->b(I)F

    .line 660
    .line 661
    .line 662
    move-result v0

    .line 663
    add-float/2addr v0, v15

    .line 664
    int-to-float v15, v10

    .line 665
    div-float/2addr v0, v15

    .line 666
    new-instance v15, Ld3/c;

    .line 667
    .line 668
    shr-long/2addr v13, v12

    .line 669
    long-to-int v13, v13

    .line 670
    invoke-static {v13}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 671
    .line 672
    .line 673
    move-result v14

    .line 674
    shr-long/2addr v4, v12

    .line 675
    long-to-int v4, v4

    .line 676
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 677
    .line 678
    .line 679
    move-result v5

    .line 680
    invoke-static {v14, v5}, Ljava/lang/Math;->min(FF)F

    .line 681
    .line 682
    .line 683
    move-result v5

    .line 684
    const v14, 0x3dcccccd    # 0.1f

    .line 685
    .line 686
    .line 687
    move/from16 v17, v12

    .line 688
    .line 689
    sub-float v12, v0, v14

    .line 690
    .line 691
    invoke-static {v13}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 692
    .line 693
    .line 694
    move-result v13

    .line 695
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 696
    .line 697
    .line 698
    move-result v4

    .line 699
    invoke-static {v13, v4}, Ljava/lang/Math;->max(FF)F

    .line 700
    .line 701
    .line 702
    move-result v4

    .line 703
    add-float/2addr v0, v14

    .line 704
    invoke-direct {v15, v5, v12, v4, v0}, Ld3/c;-><init>(FFFF)V

    .line 705
    .line 706
    .line 707
    sget-object v0, Lg4/j0;->a:Lf3/d;

    .line 708
    .line 709
    invoke-virtual {v9, v15, v8, v0}, Lg4/o;->h(Ld3/c;ILf3/d;)J

    .line 710
    .line 711
    .line 712
    move-result-wide v4

    .line 713
    goto :goto_d

    .line 714
    :goto_c
    sget-wide v4, Lg4/o0;->b:J

    .line 715
    .line 716
    :goto_d
    invoke-static {v4, v5}, Lg4/o0;->c(J)Z

    .line 717
    .line 718
    .line 719
    move-result v0

    .line 720
    if-eqz v0, :cond_25

    .line 721
    .line 722
    invoke-static {v6}, Lc2/f;->j(Ljava/lang/Object;)Landroid/view/inputmethod/HandwritingGesture;

    .line 723
    .line 724
    .line 725
    move-result-object v0

    .line 726
    invoke-static {v0, v3}, Ljp/hc;->a(Landroid/view/inputmethod/HandwritingGesture;La2/e;)I

    .line 727
    .line 728
    .line 729
    move-result v6

    .line 730
    goto/16 :goto_12

    .line 731
    .line 732
    :cond_25
    invoke-static {v4, v5}, Lg4/o0;->f(J)I

    .line 733
    .line 734
    .line 735
    move-result v0

    .line 736
    invoke-static {v4, v5}, Lg4/o0;->e(J)I

    .line 737
    .line 738
    .line 739
    move-result v9

    .line 740
    invoke-virtual {v7, v0, v9}, Lg4/g;->d(II)Lg4/g;

    .line 741
    .line 742
    .line 743
    move-result-object v0

    .line 744
    iget-object v0, v0, Lg4/g;->e:Ljava/lang/String;

    .line 745
    .line 746
    const-string v7, "\\s+"

    .line 747
    .line 748
    invoke-static {v7}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 749
    .line 750
    .line 751
    move-result-object v7

    .line 752
    const-string v9, "compile(...)"

    .line 753
    .line 754
    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 755
    .line 756
    .line 757
    const-string v9, "input"

    .line 758
    .line 759
    invoke-static {v0, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 760
    .line 761
    .line 762
    invoke-virtual {v7, v0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 763
    .line 764
    .line 765
    move-result-object v7

    .line 766
    const-string v9, "matcher(...)"

    .line 767
    .line 768
    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 769
    .line 770
    .line 771
    invoke-static {v7, v8, v0}, Ltm0/d;->c(Ljava/util/regex/Matcher;ILjava/lang/CharSequence;)Lly0/l;

    .line 772
    .line 773
    .line 774
    move-result-object v7

    .line 775
    if-nez v7, :cond_26

    .line 776
    .line 777
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 778
    .line 779
    .line 780
    move-result-object v0

    .line 781
    move v13, v11

    .line 782
    move v14, v13

    .line 783
    goto :goto_10

    .line 784
    :cond_26
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 785
    .line 786
    .line 787
    move-result v9

    .line 788
    new-instance v12, Ljava/lang/StringBuilder;

    .line 789
    .line 790
    invoke-direct {v12, v9}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 791
    .line 792
    .line 793
    move v13, v8

    .line 794
    move v14, v11

    .line 795
    :goto_e
    invoke-virtual {v7}, Lly0/l;->b()Lgy0/j;

    .line 796
    .line 797
    .line 798
    move-result-object v15

    .line 799
    iget v15, v15, Lgy0/h;->d:I

    .line 800
    .line 801
    invoke-virtual {v12, v0, v13, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;II)Ljava/lang/StringBuilder;

    .line 802
    .line 803
    .line 804
    if-ne v14, v11, :cond_27

    .line 805
    .line 806
    invoke-virtual {v7}, Lly0/l;->b()Lgy0/j;

    .line 807
    .line 808
    .line 809
    move-result-object v13

    .line 810
    iget v14, v13, Lgy0/h;->d:I

    .line 811
    .line 812
    :cond_27
    invoke-virtual {v7}, Lly0/l;->b()Lgy0/j;

    .line 813
    .line 814
    .line 815
    move-result-object v13

    .line 816
    iget v13, v13, Lgy0/h;->e:I

    .line 817
    .line 818
    add-int/lit8 v13, v13, 0x1

    .line 819
    .line 820
    const-string v15, ""

    .line 821
    .line 822
    invoke-virtual {v12, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/StringBuilder;

    .line 823
    .line 824
    .line 825
    invoke-virtual {v7}, Lly0/l;->b()Lgy0/j;

    .line 826
    .line 827
    .line 828
    move-result-object v15

    .line 829
    iget v15, v15, Lgy0/h;->e:I

    .line 830
    .line 831
    add-int/lit8 v15, v15, 0x1

    .line 832
    .line 833
    invoke-virtual {v7}, Lly0/l;->d()Lly0/l;

    .line 834
    .line 835
    .line 836
    move-result-object v7

    .line 837
    if-ge v15, v9, :cond_29

    .line 838
    .line 839
    if-nez v7, :cond_28

    .line 840
    .line 841
    goto :goto_f

    .line 842
    :cond_28
    move v13, v15

    .line 843
    goto :goto_e

    .line 844
    :cond_29
    :goto_f
    if-ge v15, v9, :cond_2a

    .line 845
    .line 846
    invoke-virtual {v12, v0, v15, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;II)Ljava/lang/StringBuilder;

    .line 847
    .line 848
    .line 849
    :cond_2a
    invoke-virtual {v12}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 850
    .line 851
    .line 852
    move-result-object v0

    .line 853
    const-string v7, "toString(...)"

    .line 854
    .line 855
    invoke-static {v0, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 856
    .line 857
    .line 858
    :goto_10
    if-eq v14, v11, :cond_2c

    .line 859
    .line 860
    if-ne v13, v11, :cond_2b

    .line 861
    .line 862
    goto :goto_11

    .line 863
    :cond_2b
    shr-long v6, v4, v17

    .line 864
    .line 865
    long-to-int v6, v6

    .line 866
    add-int v7, v6, v14

    .line 867
    .line 868
    add-int/2addr v6, v13

    .line 869
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 870
    .line 871
    .line 872
    move-result v9

    .line 873
    invoke-static {v4, v5}, Lg4/o0;->d(J)I

    .line 874
    .line 875
    .line 876
    move-result v4

    .line 877
    sub-int/2addr v4, v13

    .line 878
    sub-int/2addr v9, v4

    .line 879
    invoke-virtual {v0, v14, v9}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 880
    .line 881
    .line 882
    move-result-object v0

    .line 883
    const-string v4, "substring(...)"

    .line 884
    .line 885
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 886
    .line 887
    .line 888
    new-instance v4, Ll4/u;

    .line 889
    .line 890
    invoke-direct {v4, v7, v6}, Ll4/u;-><init>(II)V

    .line 891
    .line 892
    .line 893
    new-instance v5, Ll4/a;

    .line 894
    .line 895
    move/from16 v6, v16

    .line 896
    .line 897
    invoke-direct {v5, v0, v6}, Ll4/a;-><init>(Ljava/lang/String;I)V

    .line 898
    .line 899
    .line 900
    new-array v0, v10, [Ll4/g;

    .line 901
    .line 902
    aput-object v4, v0, v8

    .line 903
    .line 904
    aput-object v5, v0, v6

    .line 905
    .line 906
    new-instance v4, Lc2/j;

    .line 907
    .line 908
    invoke-direct {v4, v0}, Lc2/j;-><init>([Ll4/g;)V

    .line 909
    .line 910
    .line 911
    invoke-virtual {v3, v4}, La2/e;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 912
    .line 913
    .line 914
    const/4 v6, 0x1

    .line 915
    goto :goto_12

    .line 916
    :cond_2c
    :goto_11
    invoke-static {v6}, Lc2/f;->j(Ljava/lang/Object;)Landroid/view/inputmethod/HandwritingGesture;

    .line 917
    .line 918
    .line 919
    move-result-object v0

    .line 920
    invoke-static {v0, v3}, Ljp/hc;->a(Landroid/view/inputmethod/HandwritingGesture;La2/e;)I

    .line 921
    .line 922
    .line 923
    move-result v6

    .line 924
    goto :goto_12

    .line 925
    :cond_2d
    move v6, v10

    .line 926
    :cond_2e
    :goto_12
    if-nez v2, :cond_2f

    .line 927
    .line 928
    goto :goto_13

    .line 929
    :cond_2f
    if-eqz v1, :cond_30

    .line 930
    .line 931
    new-instance v0, La8/j0;

    .line 932
    .line 933
    const/4 v3, 0x1

    .line 934
    invoke-direct {v0, v2, v6, v3}, La8/j0;-><init>(Ljava/lang/Object;II)V

    .line 935
    .line 936
    .line 937
    invoke-interface {v1, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 938
    .line 939
    .line 940
    return-void

    .line 941
    :cond_30
    invoke-interface {v2, v6}, Ljava/util/function/IntConsumer;->accept(I)V

    .line 942
    .line 943
    .line 944
    :cond_31
    :goto_13
    return-void
.end method

.method public final performPrivateCommand(Ljava/lang/String;Landroid/os/Bundle;)Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lc2/q;->k:Z

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    :cond_0
    return p0
.end method

.method public final previewHandwritingGesture(Landroid/view/inputmethod/PreviewableHandwritingGesture;Landroid/os/CancellationSignal;)Z
    .locals 6

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/16 v1, 0x22

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    if-lt v0, v1, :cond_14

    .line 7
    .line 8
    iget-object v0, p0, Lc2/q;->c:Lt1/p0;

    .line 9
    .line 10
    if-eqz v0, :cond_14

    .line 11
    .line 12
    iget-object v1, v0, Lt1/p0;->j:Lg4/g;

    .line 13
    .line 14
    if-nez v1, :cond_0

    .line 15
    .line 16
    goto/16 :goto_6

    .line 17
    .line 18
    :cond_0
    invoke-virtual {v0}, Lt1/p0;->d()Lt1/j1;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    if-eqz v3, :cond_1

    .line 23
    .line 24
    iget-object v3, v3, Lt1/j1;->a:Lg4/l0;

    .line 25
    .line 26
    iget-object v3, v3, Lg4/l0;->a:Lg4/k0;

    .line 27
    .line 28
    if-eqz v3, :cond_1

    .line 29
    .line 30
    iget-object v3, v3, Lg4/k0;->a:Lg4/g;

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    const/4 v3, 0x0

    .line 34
    :goto_0
    invoke-virtual {v1, v3}, Lg4/g;->equals(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-nez v1, :cond_2

    .line 39
    .line 40
    goto/16 :goto_6

    .line 41
    .line 42
    :cond_2
    invoke-static {p1}, Lc2/f;->t(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    iget-object p0, p0, Lc2/q;->d:Le2/w0;

    .line 47
    .line 48
    const/4 v3, 0x1

    .line 49
    if-eqz v1, :cond_6

    .line 50
    .line 51
    invoke-static {p1}, Lc2/f;->n(Ljava/lang/Object;)Landroid/view/inputmethod/SelectGesture;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    if-eqz p0, :cond_12

    .line 56
    .line 57
    invoke-static {p1}, Lc2/f;->i(Landroid/view/inputmethod/SelectGesture;)Landroid/graphics/RectF;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    invoke-static {v1}, Le3/j0;->C(Landroid/graphics/RectF;)Ld3/c;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    invoke-static {p1}, Lc2/f;->c(Landroid/view/inputmethod/SelectGesture;)I

    .line 66
    .line 67
    .line 68
    move-result p1

    .line 69
    if-eq p1, v3, :cond_3

    .line 70
    .line 71
    move p1, v2

    .line 72
    goto :goto_1

    .line 73
    :cond_3
    move p1, v3

    .line 74
    :goto_1
    invoke-static {v0, v1, p1}, Ljp/ic;->g(Lt1/p0;Ld3/c;I)J

    .line 75
    .line 76
    .line 77
    move-result-wide v0

    .line 78
    iget-object p1, p0, Le2/w0;->d:Lt1/p0;

    .line 79
    .line 80
    if-eqz p1, :cond_4

    .line 81
    .line 82
    invoke-virtual {p1, v0, v1}, Lt1/p0;->f(J)V

    .line 83
    .line 84
    .line 85
    :cond_4
    iget-object p1, p0, Le2/w0;->d:Lt1/p0;

    .line 86
    .line 87
    if-eqz p1, :cond_5

    .line 88
    .line 89
    sget-wide v4, Lg4/o0;->b:J

    .line 90
    .line 91
    invoke-virtual {p1, v4, v5}, Lt1/p0;->e(J)V

    .line 92
    .line 93
    .line 94
    :cond_5
    invoke-static {v0, v1}, Lg4/o0;->c(J)Z

    .line 95
    .line 96
    .line 97
    move-result p1

    .line 98
    if-nez p1, :cond_12

    .line 99
    .line 100
    invoke-virtual {p0, v2}, Le2/w0;->s(Z)V

    .line 101
    .line 102
    .line 103
    sget-object p1, Lt1/c0;->d:Lt1/c0;

    .line 104
    .line 105
    invoke-virtual {p0, p1}, Le2/w0;->p(Lt1/c0;)V

    .line 106
    .line 107
    .line 108
    goto/16 :goto_5

    .line 109
    .line 110
    :cond_6
    invoke-static {p1}, Lc2/h;->y(Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    move-result v1

    .line 114
    if-eqz v1, :cond_a

    .line 115
    .line 116
    invoke-static {p1}, Lc2/h;->m(Ljava/lang/Object;)Landroid/view/inputmethod/DeleteGesture;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    if-eqz p0, :cond_12

    .line 121
    .line 122
    invoke-static {p1}, Lc2/f;->g(Landroid/view/inputmethod/DeleteGesture;)Landroid/graphics/RectF;

    .line 123
    .line 124
    .line 125
    move-result-object v1

    .line 126
    invoke-static {v1}, Le3/j0;->C(Landroid/graphics/RectF;)Ld3/c;

    .line 127
    .line 128
    .line 129
    move-result-object v1

    .line 130
    invoke-static {p1}, Lc2/f;->a(Landroid/view/inputmethod/DeleteGesture;)I

    .line 131
    .line 132
    .line 133
    move-result p1

    .line 134
    if-eq p1, v3, :cond_7

    .line 135
    .line 136
    move p1, v2

    .line 137
    goto :goto_2

    .line 138
    :cond_7
    move p1, v3

    .line 139
    :goto_2
    invoke-static {v0, v1, p1}, Ljp/ic;->g(Lt1/p0;Ld3/c;I)J

    .line 140
    .line 141
    .line 142
    move-result-wide v0

    .line 143
    iget-object p1, p0, Le2/w0;->d:Lt1/p0;

    .line 144
    .line 145
    if-eqz p1, :cond_8

    .line 146
    .line 147
    invoke-virtual {p1, v0, v1}, Lt1/p0;->e(J)V

    .line 148
    .line 149
    .line 150
    :cond_8
    iget-object p1, p0, Le2/w0;->d:Lt1/p0;

    .line 151
    .line 152
    if-eqz p1, :cond_9

    .line 153
    .line 154
    sget-wide v4, Lg4/o0;->b:J

    .line 155
    .line 156
    invoke-virtual {p1, v4, v5}, Lt1/p0;->f(J)V

    .line 157
    .line 158
    .line 159
    :cond_9
    invoke-static {v0, v1}, Lg4/o0;->c(J)Z

    .line 160
    .line 161
    .line 162
    move-result p1

    .line 163
    if-nez p1, :cond_12

    .line 164
    .line 165
    invoke-virtual {p0, v2}, Le2/w0;->s(Z)V

    .line 166
    .line 167
    .line 168
    sget-object p1, Lt1/c0;->d:Lt1/c0;

    .line 169
    .line 170
    invoke-virtual {p0, p1}, Le2/w0;->p(Lt1/c0;)V

    .line 171
    .line 172
    .line 173
    goto/16 :goto_5

    .line 174
    .line 175
    :cond_a
    invoke-static {p1}, Lc2/h;->C(Ljava/lang/Object;)Z

    .line 176
    .line 177
    .line 178
    move-result v1

    .line 179
    if-eqz v1, :cond_e

    .line 180
    .line 181
    invoke-static {p1}, Lc2/h;->o(Ljava/lang/Object;)Landroid/view/inputmethod/SelectRangeGesture;

    .line 182
    .line 183
    .line 184
    move-result-object p1

    .line 185
    if-eqz p0, :cond_12

    .line 186
    .line 187
    invoke-static {p1}, Lc2/h;->j(Landroid/view/inputmethod/SelectRangeGesture;)Landroid/graphics/RectF;

    .line 188
    .line 189
    .line 190
    move-result-object v1

    .line 191
    invoke-static {v1}, Le3/j0;->C(Landroid/graphics/RectF;)Ld3/c;

    .line 192
    .line 193
    .line 194
    move-result-object v1

    .line 195
    invoke-static {p1}, Lc2/h;->B(Landroid/view/inputmethod/SelectRangeGesture;)Landroid/graphics/RectF;

    .line 196
    .line 197
    .line 198
    move-result-object v4

    .line 199
    invoke-static {v4}, Le3/j0;->C(Landroid/graphics/RectF;)Ld3/c;

    .line 200
    .line 201
    .line 202
    move-result-object v4

    .line 203
    invoke-static {p1}, Lc2/f;->d(Landroid/view/inputmethod/SelectRangeGesture;)I

    .line 204
    .line 205
    .line 206
    move-result p1

    .line 207
    if-eq p1, v3, :cond_b

    .line 208
    .line 209
    move p1, v2

    .line 210
    goto :goto_3

    .line 211
    :cond_b
    move p1, v3

    .line 212
    :goto_3
    invoke-static {v0, v1, v4, p1}, Ljp/ic;->b(Lt1/p0;Ld3/c;Ld3/c;I)J

    .line 213
    .line 214
    .line 215
    move-result-wide v0

    .line 216
    iget-object p1, p0, Le2/w0;->d:Lt1/p0;

    .line 217
    .line 218
    if-eqz p1, :cond_c

    .line 219
    .line 220
    invoke-virtual {p1, v0, v1}, Lt1/p0;->f(J)V

    .line 221
    .line 222
    .line 223
    :cond_c
    iget-object p1, p0, Le2/w0;->d:Lt1/p0;

    .line 224
    .line 225
    if-eqz p1, :cond_d

    .line 226
    .line 227
    sget-wide v4, Lg4/o0;->b:J

    .line 228
    .line 229
    invoke-virtual {p1, v4, v5}, Lt1/p0;->e(J)V

    .line 230
    .line 231
    .line 232
    :cond_d
    invoke-static {v0, v1}, Lg4/o0;->c(J)Z

    .line 233
    .line 234
    .line 235
    move-result p1

    .line 236
    if-nez p1, :cond_12

    .line 237
    .line 238
    invoke-virtual {p0, v2}, Le2/w0;->s(Z)V

    .line 239
    .line 240
    .line 241
    sget-object p1, Lt1/c0;->d:Lt1/c0;

    .line 242
    .line 243
    invoke-virtual {p0, p1}, Le2/w0;->p(Lt1/c0;)V

    .line 244
    .line 245
    .line 246
    goto :goto_5

    .line 247
    :cond_e
    invoke-static {p1}, Lc2/h;->D(Ljava/lang/Object;)Z

    .line 248
    .line 249
    .line 250
    move-result v1

    .line 251
    if-eqz v1, :cond_14

    .line 252
    .line 253
    invoke-static {p1}, Lc2/h;->n(Ljava/lang/Object;)Landroid/view/inputmethod/DeleteRangeGesture;

    .line 254
    .line 255
    .line 256
    move-result-object p1

    .line 257
    if-eqz p0, :cond_12

    .line 258
    .line 259
    invoke-static {p1}, Lc2/f;->h(Landroid/view/inputmethod/DeleteRangeGesture;)Landroid/graphics/RectF;

    .line 260
    .line 261
    .line 262
    move-result-object v1

    .line 263
    invoke-static {v1}, Le3/j0;->C(Landroid/graphics/RectF;)Ld3/c;

    .line 264
    .line 265
    .line 266
    move-result-object v1

    .line 267
    invoke-static {p1}, Lc2/f;->u(Landroid/view/inputmethod/DeleteRangeGesture;)Landroid/graphics/RectF;

    .line 268
    .line 269
    .line 270
    move-result-object v4

    .line 271
    invoke-static {v4}, Le3/j0;->C(Landroid/graphics/RectF;)Ld3/c;

    .line 272
    .line 273
    .line 274
    move-result-object v4

    .line 275
    invoke-static {p1}, Lc2/f;->b(Landroid/view/inputmethod/DeleteRangeGesture;)I

    .line 276
    .line 277
    .line 278
    move-result p1

    .line 279
    if-eq p1, v3, :cond_f

    .line 280
    .line 281
    move p1, v2

    .line 282
    goto :goto_4

    .line 283
    :cond_f
    move p1, v3

    .line 284
    :goto_4
    invoke-static {v0, v1, v4, p1}, Ljp/ic;->b(Lt1/p0;Ld3/c;Ld3/c;I)J

    .line 285
    .line 286
    .line 287
    move-result-wide v0

    .line 288
    iget-object p1, p0, Le2/w0;->d:Lt1/p0;

    .line 289
    .line 290
    if-eqz p1, :cond_10

    .line 291
    .line 292
    invoke-virtual {p1, v0, v1}, Lt1/p0;->e(J)V

    .line 293
    .line 294
    .line 295
    :cond_10
    iget-object p1, p0, Le2/w0;->d:Lt1/p0;

    .line 296
    .line 297
    if-eqz p1, :cond_11

    .line 298
    .line 299
    sget-wide v4, Lg4/o0;->b:J

    .line 300
    .line 301
    invoke-virtual {p1, v4, v5}, Lt1/p0;->f(J)V

    .line 302
    .line 303
    .line 304
    :cond_11
    invoke-static {v0, v1}, Lg4/o0;->c(J)Z

    .line 305
    .line 306
    .line 307
    move-result p1

    .line 308
    if-nez p1, :cond_12

    .line 309
    .line 310
    invoke-virtual {p0, v2}, Le2/w0;->s(Z)V

    .line 311
    .line 312
    .line 313
    sget-object p1, Lt1/c0;->d:Lt1/c0;

    .line 314
    .line 315
    invoke-virtual {p0, p1}, Le2/w0;->p(Lt1/c0;)V

    .line 316
    .line 317
    .line 318
    :cond_12
    :goto_5
    if-eqz p2, :cond_13

    .line 319
    .line 320
    new-instance p1, Lc2/i;

    .line 321
    .line 322
    const/4 v0, 0x0

    .line 323
    invoke-direct {p1, p0, v0}, Lc2/i;-><init>(Ljava/lang/Object;I)V

    .line 324
    .line 325
    .line 326
    invoke-virtual {p2, p1}, Landroid/os/CancellationSignal;->setOnCancelListener(Landroid/os/CancellationSignal$OnCancelListener;)V

    .line 327
    .line 328
    .line 329
    :cond_13
    return v3

    .line 330
    :cond_14
    :goto_6
    return v2
.end method

.method public final reportFullscreenMode(Z)Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final requestCursorUpdates(I)Z
    .locals 9

    .line 1
    iget-boolean v0, p0, Lc2/q;->k:Z

    .line 2
    .line 3
    if-eqz v0, :cond_a

    .line 4
    .line 5
    and-int/lit8 v0, p1, 0x1

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    const/4 v2, 0x1

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    move v0, v2

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move v0, v1

    .line 14
    :goto_0
    and-int/lit8 v3, p1, 0x2

    .line 15
    .line 16
    if-eqz v3, :cond_1

    .line 17
    .line 18
    move v3, v2

    .line 19
    goto :goto_1

    .line 20
    :cond_1
    move v3, v1

    .line 21
    :goto_1
    sget v4, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 22
    .line 23
    const/16 v5, 0x21

    .line 24
    .line 25
    if-lt v4, v5, :cond_8

    .line 26
    .line 27
    and-int/lit8 v5, p1, 0x10

    .line 28
    .line 29
    if-eqz v5, :cond_2

    .line 30
    .line 31
    move v5, v2

    .line 32
    goto :goto_2

    .line 33
    :cond_2
    move v5, v1

    .line 34
    :goto_2
    and-int/lit8 v6, p1, 0x8

    .line 35
    .line 36
    if-eqz v6, :cond_3

    .line 37
    .line 38
    move v6, v2

    .line 39
    goto :goto_3

    .line 40
    :cond_3
    move v6, v1

    .line 41
    :goto_3
    and-int/lit8 v7, p1, 0x4

    .line 42
    .line 43
    if-eqz v7, :cond_4

    .line 44
    .line 45
    move v7, v2

    .line 46
    goto :goto_4

    .line 47
    :cond_4
    move v7, v1

    .line 48
    :goto_4
    const/16 v8, 0x22

    .line 49
    .line 50
    if-lt v4, v8, :cond_5

    .line 51
    .line 52
    and-int/lit8 p1, p1, 0x20

    .line 53
    .line 54
    if-eqz p1, :cond_5

    .line 55
    .line 56
    move v1, v2

    .line 57
    :cond_5
    if-nez v5, :cond_7

    .line 58
    .line 59
    if-nez v6, :cond_7

    .line 60
    .line 61
    if-nez v7, :cond_7

    .line 62
    .line 63
    if-nez v1, :cond_7

    .line 64
    .line 65
    if-lt v4, v8, :cond_6

    .line 66
    .line 67
    move p1, v2

    .line 68
    move v1, p1

    .line 69
    :goto_5
    move v5, v1

    .line 70
    :goto_6
    move v6, v5

    .line 71
    goto :goto_7

    .line 72
    :cond_6
    move p1, v1

    .line 73
    move v1, v2

    .line 74
    goto :goto_5

    .line 75
    :cond_7
    move p1, v1

    .line 76
    move v1, v7

    .line 77
    goto :goto_7

    .line 78
    :cond_8
    move p1, v1

    .line 79
    move v5, v2

    .line 80
    goto :goto_6

    .line 81
    :goto_7
    iget-object p0, p0, Lc2/q;->a:Lbu/c;

    .line 82
    .line 83
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast p0, Lc2/p;

    .line 86
    .line 87
    iget-object p0, p0, Lc2/p;->m:Lc2/m;

    .line 88
    .line 89
    iget-object v4, p0, Lc2/m;->c:Ljava/lang/Object;

    .line 90
    .line 91
    monitor-enter v4

    .line 92
    :try_start_0
    iput-boolean v5, p0, Lc2/m;->f:Z

    .line 93
    .line 94
    iput-boolean v6, p0, Lc2/m;->g:Z

    .line 95
    .line 96
    iput-boolean v1, p0, Lc2/m;->h:Z

    .line 97
    .line 98
    iput-boolean p1, p0, Lc2/m;->i:Z

    .line 99
    .line 100
    if-eqz v0, :cond_9

    .line 101
    .line 102
    iput-boolean v2, p0, Lc2/m;->e:Z

    .line 103
    .line 104
    iget-object p1, p0, Lc2/m;->j:Ll4/v;

    .line 105
    .line 106
    if-eqz p1, :cond_9

    .line 107
    .line 108
    invoke-virtual {p0}, Lc2/m;->a()V

    .line 109
    .line 110
    .line 111
    goto :goto_8

    .line 112
    :catchall_0
    move-exception p0

    .line 113
    goto :goto_9

    .line 114
    :cond_9
    :goto_8
    iput-boolean v3, p0, Lc2/m;->d:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 115
    .line 116
    monitor-exit v4

    .line 117
    return v2

    .line 118
    :goto_9
    monitor-exit v4

    .line 119
    throw p0

    .line 120
    :cond_a
    return v0
.end method

.method public final sendKeyEvent(Landroid/view/KeyEvent;)Z
    .locals 1

    .line 1
    iget-boolean v0, p0, Lc2/q;->k:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lc2/q;->a:Lbu/c;

    .line 6
    .line 7
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Lc2/p;

    .line 10
    .line 11
    iget-object p0, p0, Lc2/p;->k:Ljava/lang/Object;

    .line 12
    .line 13
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Landroid/view/inputmethod/BaseInputConnection;

    .line 18
    .line 19
    invoke-virtual {p0, p1}, Landroid/view/inputmethod/BaseInputConnection;->sendKeyEvent(Landroid/view/KeyEvent;)Z

    .line 20
    .line 21
    .line 22
    const/4 p0, 0x1

    .line 23
    return p0

    .line 24
    :cond_0
    return v0
.end method

.method public final setComposingRegion(II)Z
    .locals 2

    .line 1
    iget-boolean v0, p0, Lc2/q;->k:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    new-instance v1, Ll4/s;

    .line 6
    .line 7
    invoke-direct {v1, p1, p2}, Ll4/s;-><init>(II)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, v1}, Lc2/q;->a(Ll4/g;)V

    .line 11
    .line 12
    .line 13
    :cond_0
    return v0
.end method

.method public final setComposingText(Ljava/lang/CharSequence;I)Z
    .locals 2

    .line 1
    iget-boolean v0, p0, Lc2/q;->k:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    new-instance v1, Ll4/t;

    .line 6
    .line 7
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    invoke-direct {v1, p1, p2}, Ll4/t;-><init>(Ljava/lang/String;I)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0, v1}, Lc2/q;->a(Ll4/g;)V

    .line 15
    .line 16
    .line 17
    :cond_0
    return v0
.end method

.method public final setSelection(II)Z
    .locals 1

    .line 1
    iget-boolean v0, p0, Lc2/q;->k:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Ll4/u;

    .line 6
    .line 7
    invoke-direct {v0, p1, p2}, Ll4/u;-><init>(II)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, v0}, Lc2/q;->a(Ll4/g;)V

    .line 11
    .line 12
    .line 13
    const/4 p0, 0x1

    .line 14
    return p0

    .line 15
    :cond_0
    return v0
.end method
