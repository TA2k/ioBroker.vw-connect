.class public final Lcom/google/firebase/messaging/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lc1/g2;
.implements Lju/b;
.implements Ll9/j;


# static fields
.field public static i:Lcom/google/firebase/messaging/w;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;

.field public g:Ljava/lang/Object;

.field public h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(I)V
    .locals 3

    iput p1, p0, Lcom/google/firebase/messaging/w;->d:I

    sparse-switch p1, :sswitch_data_0

    .line 345
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 p1, 0x0

    .line 346
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 347
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 348
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 349
    new-instance p1, Ljava/util/ArrayDeque;

    invoke-direct {p1}, Ljava/util/ArrayDeque;-><init>()V

    iput-object p1, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    return-void

    .line 350
    :sswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 351
    new-instance p1, Lw7/p;

    invoke-direct {p1}, Lw7/p;-><init>()V

    iput-object p1, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 352
    new-instance p1, Lw7/p;

    invoke-direct {p1}, Lw7/p;-><init>()V

    iput-object p1, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 353
    new-instance p1, Lo9/a;

    invoke-direct {p1}, Lo9/a;-><init>()V

    iput-object p1, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    return-void

    .line 354
    :sswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 355
    new-instance p1, La5/e;

    const/16 v0, 0xa

    invoke-direct {p1, v0}, La5/e;-><init>(I)V

    iput-object p1, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 356
    new-instance p1, Landroidx/collection/a1;

    const/4 v0, 0x0

    .line 357
    invoke-direct {p1, v0}, Landroidx/collection/a1;-><init>(I)V

    .line 358
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 359
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 360
    new-instance p1, Ljava/util/HashSet;

    invoke-direct {p1}, Ljava/util/HashSet;-><init>()V

    iput-object p1, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    return-void

    .line 361
    :sswitch_2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Lcom/google/android/gms/internal/measurement/u;

    const/4 v0, 0x0

    invoke-direct {p1, v0}, Lcom/google/android/gms/internal/measurement/u;-><init>(I)V

    iput-object p1, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    new-instance v0, Lcom/google/firebase/messaging/w;

    const/4 v1, 0x0

    .line 362
    invoke-direct {v0, v1, p1}, Lcom/google/firebase/messaging/w;-><init>(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/u;)V

    iput-object v0, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 363
    invoke-virtual {v0}, Lcom/google/firebase/messaging/w;->z()Lcom/google/firebase/messaging/w;

    move-result-object p1

    iput-object p1, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    new-instance p1, Lcom/google/android/gms/internal/measurement/a6;

    const/4 v1, 0x1

    .line 364
    invoke-direct {p1, v1}, Lcom/google/android/gms/internal/measurement/a6;-><init>(I)V

    iput-object p1, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    new-instance p0, Lcom/google/android/gms/internal/measurement/z9;

    .line 365
    invoke-direct {p0, p1}, Lcom/google/android/gms/internal/measurement/z9;-><init>(Lcom/google/android/gms/internal/measurement/a6;)V

    const-string v1, "require"

    invoke-virtual {v0, v1, p0}, Lcom/google/firebase/messaging/w;->B(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/o;)V

    .line 366
    iget-object p0, p1, Lcom/google/android/gms/internal/measurement/a6;->a:Ljava/lang/Object;

    check-cast p0, Ljava/util/HashMap;

    const-string p1, "internal.platform"

    sget-object v1, Lcom/google/android/gms/internal/measurement/e1;->a:Lcom/google/android/gms/internal/measurement/e1;

    invoke-virtual {p0, p1, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 367
    new-instance p0, Lcom/google/android/gms/internal/measurement/h;

    const-wide/16 v1, 0x0

    .line 368
    invoke-static {v1, v2}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object p1

    invoke-direct {p0, p1}, Lcom/google/android/gms/internal/measurement/h;-><init>(Ljava/lang/Double;)V

    const-string p1, "runtime.counter"

    invoke-virtual {v0, p1, p0}, Lcom/google/firebase/messaging/w;->B(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/o;)V

    return-void

    .line 369
    :sswitch_3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 370
    new-instance p1, Landroidx/collection/f;

    const/4 v0, 0x0

    .line 371
    invoke-direct {p1, v0}, Landroidx/collection/a1;-><init>(I)V

    .line 372
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 373
    new-instance p1, Landroid/util/SparseArray;

    invoke-direct {p1}, Landroid/util/SparseArray;-><init>()V

    iput-object p1, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 374
    new-instance p1, Landroidx/collection/u;

    const/4 v1, 0x0

    .line 375
    invoke-direct {p1, v1}, Landroidx/collection/u;-><init>(Ljava/lang/Object;)V

    .line 376
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 377
    new-instance p1, Landroidx/collection/f;

    .line 378
    invoke-direct {p1, v0}, Landroidx/collection/a1;-><init>(I)V

    .line 379
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    return-void

    :sswitch_data_0
    .sparse-switch
        0x4 -> :sswitch_3
        0x6 -> :sswitch_2
        0x12 -> :sswitch_1
        0x16 -> :sswitch_0
    .end sparse-switch
.end method

.method public synthetic constructor <init>(IZ)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/google/firebase/messaging/w;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 4

    const/4 v0, 0x2

    iput v0, p0, Lcom/google/firebase/messaging/w;->d:I

    .line 40
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 41
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 42
    new-instance v0, Lav/a;

    invoke-direct {v0, p1}, Lav/a;-><init>(Landroid/content/Context;)V

    .line 43
    invoke-static {p1}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    move-result-object v1

    const v2, 0x7f0d001d

    const/4 v3, 0x0

    invoke-virtual {v1, v2, v3}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;)Landroid/view/View;

    move-result-object v1

    check-cast v1, Landroid/view/ViewGroup;

    iput-object v1, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    const/4 v2, 0x0

    .line 44
    invoke-virtual {v1, v2}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v1

    check-cast v1, Lcom/google/maps/android/ui/RotationLayout;

    iput-object v1, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    const v2, 0x7f0a004f

    .line 45
    invoke-virtual {v1, v2}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    move-result-object v1

    check-cast v1, Landroid/widget/TextView;

    iput-object v1, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    const/4 v1, -0x1

    .line 46
    iput v1, v0, Lav/a;->c:I

    .line 47
    invoke-virtual {p0, v0}, Lcom/google/firebase/messaging/w;->r(Landroid/graphics/drawable/Drawable;)V

    .line 48
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    check-cast p0, Landroid/widget/TextView;

    if-eqz p0, :cond_0

    const v0, 0x7f130574

    .line 49
    invoke-virtual {p0, p1, v0}, Landroid/widget/TextView;->setTextAppearance(Landroid/content/Context;I)V

    :cond_0
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/view/ActionMode$Callback;)V
    .locals 1

    const/16 v0, 0x11

    iput v0, p0, Lcom/google/firebase/messaging/w;->d:I

    .line 380
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 381
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 382
    iput-object p2, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 383
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 384
    new-instance p1, Landroidx/collection/a1;

    const/4 p2, 0x0

    .line 385
    invoke-direct {p1, p2}, Landroidx/collection/a1;-><init>(I)V

    .line 386
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/graphics/Typeface;Lt6/b;)V
    .locals 7

    const/16 v0, 0x1c

    iput v0, p0, Lcom/google/firebase/messaging/w;->d:I

    .line 234
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 235
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 236
    iput-object p2, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 237
    new-instance p1, Ls6/q;

    const/16 v0, 0x400

    invoke-direct {p1, v0}, Ls6/q;-><init>(I)V

    iput-object p1, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    const/4 p1, 0x6

    .line 238
    invoke-virtual {p2, p1}, Ld6/h0;->a(I)I

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    .line 239
    iget v2, p2, Ld6/h0;->d:I

    add-int/2addr v0, v2

    .line 240
    iget-object v2, p2, Ld6/h0;->g:Ljava/lang/Object;

    check-cast v2, Ljava/nio/ByteBuffer;

    invoke-virtual {v2, v0}, Ljava/nio/ByteBuffer;->getInt(I)I

    move-result v2

    add-int/2addr v2, v0

    .line 241
    iget-object v0, p2, Ld6/h0;->g:Ljava/lang/Object;

    check-cast v0, Ljava/nio/ByteBuffer;

    invoke-virtual {v0, v2}, Ljava/nio/ByteBuffer;->getInt(I)I

    move-result v0

    goto :goto_0

    :cond_0
    move v0, v1

    :goto_0
    mul-int/lit8 v0, v0, 0x2

    .line 242
    new-array v0, v0, [C

    iput-object v0, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 243
    invoke-virtual {p2, p1}, Ld6/h0;->a(I)I

    move-result p1

    if-eqz p1, :cond_1

    .line 244
    iget v0, p2, Ld6/h0;->d:I

    add-int/2addr p1, v0

    .line 245
    iget-object v0, p2, Ld6/h0;->g:Ljava/lang/Object;

    check-cast v0, Ljava/nio/ByteBuffer;

    invoke-virtual {v0, p1}, Ljava/nio/ByteBuffer;->getInt(I)I

    move-result v0

    add-int/2addr v0, p1

    .line 246
    iget-object p1, p2, Ld6/h0;->g:Ljava/lang/Object;

    check-cast p1, Ljava/nio/ByteBuffer;

    invoke-virtual {p1, v0}, Ljava/nio/ByteBuffer;->getInt(I)I

    move-result p1

    goto :goto_1

    :cond_1
    move p1, v1

    :goto_1
    move p2, v1

    :goto_2
    if-ge p2, p1, :cond_6

    .line 247
    new-instance v0, Ls6/t;

    invoke-direct {v0, p0, p2}, Ls6/t;-><init>(Lcom/google/firebase/messaging/w;I)V

    .line 248
    invoke-virtual {v0}, Ls6/t;->b()Lt6/a;

    move-result-object v2

    const/4 v3, 0x4

    .line 249
    invoke-virtual {v2, v3}, Ld6/h0;->a(I)I

    move-result v3

    if-eqz v3, :cond_2

    iget-object v4, v2, Ld6/h0;->g:Ljava/lang/Object;

    check-cast v4, Ljava/nio/ByteBuffer;

    iget v2, v2, Ld6/h0;->d:I

    add-int/2addr v3, v2

    invoke-virtual {v4, v3}, Ljava/nio/ByteBuffer;->getInt(I)I

    move-result v2

    goto :goto_3

    :cond_2
    move v2, v1

    .line 250
    :goto_3
    iget-object v3, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    check-cast v3, [C

    mul-int/lit8 v4, p2, 0x2

    invoke-static {v2, v3, v4}, Ljava/lang/Character;->toChars(I[CI)I

    .line 251
    invoke-virtual {v0}, Ls6/t;->b()Lt6/a;

    move-result-object v2

    const/16 v3, 0x10

    .line 252
    invoke-virtual {v2, v3}, Ld6/h0;->a(I)I

    move-result v4

    if-eqz v4, :cond_3

    .line 253
    iget v5, v2, Ld6/h0;->d:I

    add-int/2addr v4, v5

    .line 254
    iget-object v5, v2, Ld6/h0;->g:Ljava/lang/Object;

    check-cast v5, Ljava/nio/ByteBuffer;

    invoke-virtual {v5, v4}, Ljava/nio/ByteBuffer;->getInt(I)I

    move-result v5

    add-int/2addr v5, v4

    .line 255
    iget-object v2, v2, Ld6/h0;->g:Ljava/lang/Object;

    check-cast v2, Ljava/nio/ByteBuffer;

    invoke-virtual {v2, v5}, Ljava/nio/ByteBuffer;->getInt(I)I

    move-result v2

    goto :goto_4

    :cond_3
    move v2, v1

    :goto_4
    const/4 v4, 0x1

    if-lez v2, :cond_4

    move v2, v4

    goto :goto_5

    :cond_4
    move v2, v1

    .line 256
    :goto_5
    const-string v5, "invalid metadata codepoint length"

    invoke-static {v2, v5}, Ljp/ed;->b(ZLjava/lang/String;)V

    .line 257
    iget-object v2, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    check-cast v2, Ls6/q;

    .line 258
    invoke-virtual {v0}, Ls6/t;->b()Lt6/a;

    move-result-object v5

    .line 259
    invoke-virtual {v5, v3}, Ld6/h0;->a(I)I

    move-result v3

    if-eqz v3, :cond_5

    .line 260
    iget v6, v5, Ld6/h0;->d:I

    add-int/2addr v3, v6

    .line 261
    iget-object v6, v5, Ld6/h0;->g:Ljava/lang/Object;

    check-cast v6, Ljava/nio/ByteBuffer;

    invoke-virtual {v6, v3}, Ljava/nio/ByteBuffer;->getInt(I)I

    move-result v6

    add-int/2addr v6, v3

    .line 262
    iget-object v3, v5, Ld6/h0;->g:Ljava/lang/Object;

    check-cast v3, Ljava/nio/ByteBuffer;

    invoke-virtual {v3, v6}, Ljava/nio/ByteBuffer;->getInt(I)I

    move-result v3

    goto :goto_6

    :cond_5
    move v3, v1

    :goto_6
    sub-int/2addr v3, v4

    .line 263
    invoke-virtual {v2, v0, v1, v3}, Ls6/q;->a(Ls6/t;II)V

    add-int/lit8 p2, p2, 0x1

    goto :goto_2

    :cond_6
    return-void
.end method

.method public constructor <init>(Landroid/security/identity/IdentityCredential;)V
    .locals 1

    const/16 v0, 0x19

    iput v0, p0, Lcom/google/firebase/messaging/w;->d:I

    .line 402
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 403
    iput-object v0, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 404
    iput-object v0, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 405
    iput-object v0, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 406
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroidx/core/app/x;)V
    .locals 16

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    const/4 v2, 0x1

    iput v2, v0, Lcom/google/firebase/messaging/w;->d:I

    .line 74
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 75
    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 76
    new-instance v2, Landroid/os/Bundle;

    invoke-direct {v2}, Landroid/os/Bundle;-><init>()V

    iput-object v2, v0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 77
    iput-object v1, v0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 78
    iget-object v2, v1, Landroidx/core/app/x;->a:Landroid/content/Context;

    iget-object v3, v1, Landroidx/core/app/x;->d:Ljava/util/ArrayList;

    iput-object v2, v0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 79
    iget-object v4, v1, Landroidx/core/app/x;->u:Ljava/lang/String;

    .line 80
    new-instance v5, Landroid/app/Notification$Builder;

    invoke-direct {v5, v2, v4}, Landroid/app/Notification$Builder;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    .line 81
    iput-object v5, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 82
    iget-object v4, v1, Landroidx/core/app/x;->y:Landroid/app/Notification;

    .line 83
    iget-wide v6, v4, Landroid/app/Notification;->when:J

    invoke-virtual {v5, v6, v7}, Landroid/app/Notification$Builder;->setWhen(J)Landroid/app/Notification$Builder;

    move-result-object v6

    iget v7, v4, Landroid/app/Notification;->icon:I

    iget v8, v4, Landroid/app/Notification;->iconLevel:I

    .line 84
    invoke-virtual {v6, v7, v8}, Landroid/app/Notification$Builder;->setSmallIcon(II)Landroid/app/Notification$Builder;

    move-result-object v6

    iget-object v7, v4, Landroid/app/Notification;->contentView:Landroid/widget/RemoteViews;

    .line 85
    invoke-virtual {v6, v7}, Landroid/app/Notification$Builder;->setContent(Landroid/widget/RemoteViews;)Landroid/app/Notification$Builder;

    move-result-object v6

    iget-object v7, v4, Landroid/app/Notification;->tickerText:Ljava/lang/CharSequence;

    const/4 v8, 0x0

    .line 86
    invoke-virtual {v6, v7, v8}, Landroid/app/Notification$Builder;->setTicker(Ljava/lang/CharSequence;Landroid/widget/RemoteViews;)Landroid/app/Notification$Builder;

    move-result-object v6

    iget-object v7, v4, Landroid/app/Notification;->vibrate:[J

    .line 87
    invoke-virtual {v6, v7}, Landroid/app/Notification$Builder;->setVibrate([J)Landroid/app/Notification$Builder;

    move-result-object v6

    iget v7, v4, Landroid/app/Notification;->ledARGB:I

    iget v9, v4, Landroid/app/Notification;->ledOnMS:I

    iget v10, v4, Landroid/app/Notification;->ledOffMS:I

    .line 88
    invoke-virtual {v6, v7, v9, v10}, Landroid/app/Notification$Builder;->setLights(III)Landroid/app/Notification$Builder;

    move-result-object v6

    iget v7, v4, Landroid/app/Notification;->flags:I

    and-int/lit8 v7, v7, 0x2

    const/4 v9, 0x1

    const/4 v10, 0x0

    if-eqz v7, :cond_0

    move v7, v9

    goto :goto_0

    :cond_0
    move v7, v10

    .line 89
    :goto_0
    invoke-virtual {v6, v7}, Landroid/app/Notification$Builder;->setOngoing(Z)Landroid/app/Notification$Builder;

    move-result-object v6

    iget v7, v4, Landroid/app/Notification;->flags:I

    and-int/lit8 v7, v7, 0x8

    if-eqz v7, :cond_1

    move v7, v9

    goto :goto_1

    :cond_1
    move v7, v10

    .line 90
    :goto_1
    invoke-virtual {v6, v7}, Landroid/app/Notification$Builder;->setOnlyAlertOnce(Z)Landroid/app/Notification$Builder;

    move-result-object v6

    iget v7, v4, Landroid/app/Notification;->flags:I

    and-int/lit8 v7, v7, 0x10

    if-eqz v7, :cond_2

    move v7, v9

    goto :goto_2

    :cond_2
    move v7, v10

    .line 91
    :goto_2
    invoke-virtual {v6, v7}, Landroid/app/Notification$Builder;->setAutoCancel(Z)Landroid/app/Notification$Builder;

    move-result-object v6

    iget v7, v4, Landroid/app/Notification;->defaults:I

    .line 92
    invoke-virtual {v6, v7}, Landroid/app/Notification$Builder;->setDefaults(I)Landroid/app/Notification$Builder;

    move-result-object v6

    iget-object v7, v1, Landroidx/core/app/x;->e:Ljava/lang/CharSequence;

    .line 93
    invoke-virtual {v6, v7}, Landroid/app/Notification$Builder;->setContentTitle(Ljava/lang/CharSequence;)Landroid/app/Notification$Builder;

    move-result-object v6

    iget-object v7, v1, Landroidx/core/app/x;->f:Ljava/lang/CharSequence;

    .line 94
    invoke-virtual {v6, v7}, Landroid/app/Notification$Builder;->setContentText(Ljava/lang/CharSequence;)Landroid/app/Notification$Builder;

    move-result-object v6

    .line 95
    invoke-virtual {v6, v8}, Landroid/app/Notification$Builder;->setContentInfo(Ljava/lang/CharSequence;)Landroid/app/Notification$Builder;

    move-result-object v6

    iget-object v7, v1, Landroidx/core/app/x;->g:Landroid/app/PendingIntent;

    .line 96
    invoke-virtual {v6, v7}, Landroid/app/Notification$Builder;->setContentIntent(Landroid/app/PendingIntent;)Landroid/app/Notification$Builder;

    move-result-object v6

    iget-object v7, v4, Landroid/app/Notification;->deleteIntent:Landroid/app/PendingIntent;

    .line 97
    invoke-virtual {v6, v7}, Landroid/app/Notification$Builder;->setDeleteIntent(Landroid/app/PendingIntent;)Landroid/app/Notification$Builder;

    move-result-object v6

    iget v7, v4, Landroid/app/Notification;->flags:I

    and-int/lit16 v7, v7, 0x80

    if-eqz v7, :cond_3

    goto :goto_3

    :cond_3
    move v9, v10

    .line 98
    :goto_3
    invoke-virtual {v6, v8, v9}, Landroid/app/Notification$Builder;->setFullScreenIntent(Landroid/app/PendingIntent;Z)Landroid/app/Notification$Builder;

    move-result-object v6

    iget v7, v1, Landroidx/core/app/x;->i:I

    .line 99
    invoke-virtual {v6, v7}, Landroid/app/Notification$Builder;->setNumber(I)Landroid/app/Notification$Builder;

    move-result-object v6

    .line 100
    invoke-virtual {v6, v10, v10, v10}, Landroid/app/Notification$Builder;->setProgress(IIZ)Landroid/app/Notification$Builder;

    .line 101
    iget-object v6, v1, Landroidx/core/app/x;->h:Landroidx/core/graphics/drawable/IconCompat;

    if-nez v6, :cond_4

    move-object v2, v8

    goto :goto_4

    :cond_4
    invoke-virtual {v6, v2}, Landroidx/core/graphics/drawable/IconCompat;->f(Landroid/content/Context;)Landroid/graphics/drawable/Icon;

    move-result-object v2

    .line 102
    :goto_4
    invoke-virtual {v5, v2}, Landroid/app/Notification$Builder;->setLargeIcon(Landroid/graphics/drawable/Icon;)Landroid/app/Notification$Builder;

    .line 103
    invoke-virtual {v5, v8}, Landroid/app/Notification$Builder;->setSubText(Ljava/lang/CharSequence;)Landroid/app/Notification$Builder;

    move-result-object v2

    .line 104
    invoke-virtual {v2, v10}, Landroid/app/Notification$Builder;->setUsesChronometer(Z)Landroid/app/Notification$Builder;

    move-result-object v2

    .line 105
    iget v5, v1, Landroidx/core/app/x;->j:I

    invoke-virtual {v2, v5}, Landroid/app/Notification$Builder;->setPriority(I)Landroid/app/Notification$Builder;

    .line 106
    iget-object v2, v1, Landroidx/core/app/x;->b:Ljava/util/ArrayList;

    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_5
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    const-string v6, "android.support.allowGeneratedReplies"

    if-eqz v5, :cond_8

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Landroidx/core/app/r;

    .line 107
    sget v7, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 108
    invoke-virtual {v5}, Landroidx/core/app/r;->a()Landroidx/core/graphics/drawable/IconCompat;

    move-result-object v9

    iget-boolean v11, v5, Landroidx/core/app/r;->c:Z

    iget-object v12, v5, Landroidx/core/app/r;->a:Landroid/os/Bundle;

    if-eqz v9, :cond_5

    .line 109
    invoke-virtual {v9, v8}, Landroidx/core/graphics/drawable/IconCompat;->f(Landroid/content/Context;)Landroid/graphics/drawable/Icon;

    move-result-object v9

    goto :goto_6

    :cond_5
    move-object v9, v8

    .line 110
    :goto_6
    iget-object v13, v5, Landroidx/core/app/r;->f:Ljava/lang/CharSequence;

    .line 111
    iget-object v14, v5, Landroidx/core/app/r;->g:Landroid/app/PendingIntent;

    .line 112
    new-instance v15, Landroid/app/Notification$Action$Builder;

    invoke-direct {v15, v9, v13, v14}, Landroid/app/Notification$Action$Builder;-><init>(Landroid/graphics/drawable/Icon;Ljava/lang/CharSequence;Landroid/app/PendingIntent;)V

    if-eqz v12, :cond_6

    .line 113
    new-instance v9, Landroid/os/Bundle;

    invoke-direct {v9, v12}, Landroid/os/Bundle;-><init>(Landroid/os/Bundle;)V

    goto :goto_7

    .line 114
    :cond_6
    new-instance v9, Landroid/os/Bundle;

    invoke-direct {v9}, Landroid/os/Bundle;-><init>()V

    .line 115
    :goto_7
    invoke-virtual {v9, v6, v11}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 116
    invoke-virtual {v15, v11}, Landroid/app/Notification$Action$Builder;->setAllowGeneratedReplies(Z)Landroid/app/Notification$Action$Builder;

    .line 117
    const-string v6, "android.support.action.semanticAction"

    invoke-virtual {v9, v6, v10}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 118
    invoke-virtual {v15, v10}, Landroid/app/Notification$Action$Builder;->setSemanticAction(I)Landroid/app/Notification$Action$Builder;

    .line 119
    invoke-virtual {v15, v10}, Landroid/app/Notification$Action$Builder;->setContextual(Z)Landroid/app/Notification$Action$Builder;

    const/16 v6, 0x1f

    if-lt v7, v6, :cond_7

    .line 120
    invoke-static {v15}, Landroidx/core/app/f0;->a(Landroid/app/Notification$Action$Builder;)V

    .line 121
    :cond_7
    const-string v6, "android.support.action.showsUserInterface"

    .line 122
    iget-boolean v5, v5, Landroidx/core/app/r;->d:Z

    .line 123
    invoke-virtual {v9, v6, v5}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 124
    invoke-virtual {v15, v9}, Landroid/app/Notification$Action$Builder;->addExtras(Landroid/os/Bundle;)Landroid/app/Notification$Action$Builder;

    .line 125
    iget-object v5, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    check-cast v5, Landroid/app/Notification$Builder;

    .line 126
    invoke-virtual {v15}, Landroid/app/Notification$Action$Builder;->build()Landroid/app/Notification$Action;

    move-result-object v6

    .line 127
    invoke-virtual {v5, v6}, Landroid/app/Notification$Builder;->addAction(Landroid/app/Notification$Action;)Landroid/app/Notification$Builder;

    goto :goto_5

    .line 128
    :cond_8
    iget-object v2, v1, Landroidx/core/app/x;->p:Landroid/os/Bundle;

    if-eqz v2, :cond_9

    .line 129
    iget-object v5, v0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    check-cast v5, Landroid/os/Bundle;

    invoke-virtual {v5, v2}, Landroid/os/Bundle;->putAll(Landroid/os/Bundle;)V

    .line 130
    :cond_9
    iget-object v2, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    check-cast v2, Landroid/app/Notification$Builder;

    iget-boolean v5, v1, Landroidx/core/app/x;->k:Z

    invoke-virtual {v2, v5}, Landroid/app/Notification$Builder;->setShowWhen(Z)Landroid/app/Notification$Builder;

    .line 131
    iget-object v2, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    check-cast v2, Landroid/app/Notification$Builder;

    iget-boolean v5, v1, Landroidx/core/app/x;->o:Z

    .line 132
    invoke-virtual {v2, v5}, Landroid/app/Notification$Builder;->setLocalOnly(Z)Landroid/app/Notification$Builder;

    .line 133
    iget-object v2, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    check-cast v2, Landroid/app/Notification$Builder;

    iget-object v5, v1, Landroidx/core/app/x;->m:Ljava/lang/String;

    .line 134
    invoke-virtual {v2, v5}, Landroid/app/Notification$Builder;->setGroup(Ljava/lang/String;)Landroid/app/Notification$Builder;

    .line 135
    iget-object v2, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    check-cast v2, Landroid/app/Notification$Builder;

    .line 136
    invoke-virtual {v2, v8}, Landroid/app/Notification$Builder;->setSortKey(Ljava/lang/String;)Landroid/app/Notification$Builder;

    .line 137
    iget-object v2, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    check-cast v2, Landroid/app/Notification$Builder;

    iget-boolean v5, v1, Landroidx/core/app/x;->n:Z

    .line 138
    invoke-virtual {v2, v5}, Landroid/app/Notification$Builder;->setGroupSummary(Z)Landroid/app/Notification$Builder;

    .line 139
    iget-object v2, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    check-cast v2, Landroid/app/Notification$Builder;

    .line 140
    invoke-virtual {v2, v8}, Landroid/app/Notification$Builder;->setCategory(Ljava/lang/String;)Landroid/app/Notification$Builder;

    .line 141
    iget-object v2, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    check-cast v2, Landroid/app/Notification$Builder;

    iget v5, v1, Landroidx/core/app/x;->q:I

    .line 142
    invoke-virtual {v2, v5}, Landroid/app/Notification$Builder;->setColor(I)Landroid/app/Notification$Builder;

    .line 143
    iget-object v2, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    check-cast v2, Landroid/app/Notification$Builder;

    iget v5, v1, Landroidx/core/app/x;->r:I

    .line 144
    invoke-virtual {v2, v5}, Landroid/app/Notification$Builder;->setVisibility(I)Landroid/app/Notification$Builder;

    .line 145
    iget-object v2, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    check-cast v2, Landroid/app/Notification$Builder;

    .line 146
    invoke-virtual {v2, v8}, Landroid/app/Notification$Builder;->setPublicVersion(Landroid/app/Notification;)Landroid/app/Notification$Builder;

    .line 147
    iget-object v2, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    check-cast v2, Landroid/app/Notification$Builder;

    iget-object v5, v4, Landroid/app/Notification;->sound:Landroid/net/Uri;

    iget-object v4, v4, Landroid/app/Notification;->audioAttributes:Landroid/media/AudioAttributes;

    .line 148
    invoke-virtual {v2, v5, v4}, Landroid/app/Notification$Builder;->setSound(Landroid/net/Uri;Landroid/media/AudioAttributes;)Landroid/app/Notification$Builder;

    .line 149
    iget-object v2, v1, Landroidx/core/app/x;->z:Ljava/util/ArrayList;

    if-eqz v2, :cond_a

    .line 150
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v4

    if-nez v4, :cond_a

    .line 151
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_8
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_a

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    .line 152
    iget-object v5, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    check-cast v5, Landroid/app/Notification$Builder;

    .line 153
    invoke-virtual {v5, v4}, Landroid/app/Notification$Builder;->addPerson(Ljava/lang/String;)Landroid/app/Notification$Builder;

    goto :goto_8

    .line 154
    :cond_a
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    move-result v2

    if-lez v2, :cond_11

    .line 155
    iget-object v2, v1, Landroidx/core/app/x;->p:Landroid/os/Bundle;

    if-nez v2, :cond_b

    .line 156
    new-instance v2, Landroid/os/Bundle;

    invoke-direct {v2}, Landroid/os/Bundle;-><init>()V

    iput-object v2, v1, Landroidx/core/app/x;->p:Landroid/os/Bundle;

    .line 157
    :cond_b
    iget-object v2, v1, Landroidx/core/app/x;->p:Landroid/os/Bundle;

    .line 158
    const-string v4, "android.car.EXTENSIONS"

    invoke-virtual {v2, v4}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    move-result-object v2

    if-nez v2, :cond_c

    .line 159
    new-instance v2, Landroid/os/Bundle;

    invoke-direct {v2}, Landroid/os/Bundle;-><init>()V

    .line 160
    :cond_c
    new-instance v5, Landroid/os/Bundle;

    invoke-direct {v5, v2}, Landroid/os/Bundle;-><init>(Landroid/os/Bundle;)V

    .line 161
    new-instance v7, Landroid/os/Bundle;

    invoke-direct {v7}, Landroid/os/Bundle;-><init>()V

    move v9, v10

    .line 162
    :goto_9
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    move-result v11

    if-ge v9, v11, :cond_f

    .line 163
    invoke-static {v9}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;

    move-result-object v11

    .line 164
    invoke-virtual {v3, v9}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Landroidx/core/app/r;

    .line 165
    new-instance v13, Landroid/os/Bundle;

    invoke-direct {v13}, Landroid/os/Bundle;-><init>()V

    .line 166
    invoke-virtual {v12}, Landroidx/core/app/r;->a()Landroidx/core/graphics/drawable/IconCompat;

    move-result-object v14

    iget-object v15, v12, Landroidx/core/app/r;->a:Landroid/os/Bundle;

    if-eqz v14, :cond_d

    .line 167
    invoke-virtual {v14}, Landroidx/core/graphics/drawable/IconCompat;->b()I

    move-result v14

    goto :goto_a

    :cond_d
    move v14, v10

    :goto_a
    const-string v10, "icon"

    invoke-virtual {v13, v10, v14}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 168
    const-string v10, "title"

    .line 169
    iget-object v14, v12, Landroidx/core/app/r;->f:Ljava/lang/CharSequence;

    .line 170
    invoke-virtual {v13, v10, v14}, Landroid/os/Bundle;->putCharSequence(Ljava/lang/String;Ljava/lang/CharSequence;)V

    .line 171
    const-string v10, "actionIntent"

    .line 172
    iget-object v14, v12, Landroidx/core/app/r;->g:Landroid/app/PendingIntent;

    .line 173
    invoke-virtual {v13, v10, v14}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    if-eqz v15, :cond_e

    .line 174
    new-instance v10, Landroid/os/Bundle;

    invoke-direct {v10, v15}, Landroid/os/Bundle;-><init>(Landroid/os/Bundle;)V

    goto :goto_b

    .line 175
    :cond_e
    new-instance v10, Landroid/os/Bundle;

    invoke-direct {v10}, Landroid/os/Bundle;-><init>()V

    .line 176
    :goto_b
    iget-boolean v14, v12, Landroidx/core/app/r;->c:Z

    .line 177
    invoke-virtual {v10, v6, v14}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 178
    const-string v14, "extras"

    invoke-virtual {v13, v14, v10}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 179
    const-string v10, "remoteInputs"

    invoke-virtual {v13, v10, v8}, Landroid/os/Bundle;->putParcelableArray(Ljava/lang/String;[Landroid/os/Parcelable;)V

    .line 180
    const-string v10, "showsUserInterface"

    .line 181
    iget-boolean v12, v12, Landroidx/core/app/r;->d:Z

    .line 182
    invoke-virtual {v13, v10, v12}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 183
    const-string v10, "semanticAction"

    const/4 v12, 0x0

    invoke-virtual {v13, v10, v12}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 184
    invoke-virtual {v7, v11, v13}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    add-int/lit8 v9, v9, 0x1

    const/4 v10, 0x0

    goto :goto_9

    .line 185
    :cond_f
    const-string v3, "invisible_actions"

    invoke-virtual {v2, v3, v7}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 186
    invoke-virtual {v5, v3, v7}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 187
    iget-object v3, v1, Landroidx/core/app/x;->p:Landroid/os/Bundle;

    if-nez v3, :cond_10

    .line 188
    new-instance v3, Landroid/os/Bundle;

    invoke-direct {v3}, Landroid/os/Bundle;-><init>()V

    iput-object v3, v1, Landroidx/core/app/x;->p:Landroid/os/Bundle;

    .line 189
    :cond_10
    iget-object v3, v1, Landroidx/core/app/x;->p:Landroid/os/Bundle;

    .line 190
    invoke-virtual {v3, v4, v2}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 191
    iget-object v2, v0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    check-cast v2, Landroid/os/Bundle;

    invoke-virtual {v2, v4, v5}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 192
    :cond_11
    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 193
    iget-object v3, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    check-cast v3, Landroid/app/Notification$Builder;

    iget-object v4, v1, Landroidx/core/app/x;->p:Landroid/os/Bundle;

    invoke-virtual {v3, v4}, Landroid/app/Notification$Builder;->setExtras(Landroid/os/Bundle;)Landroid/app/Notification$Builder;

    .line 194
    iget-object v3, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    check-cast v3, Landroid/app/Notification$Builder;

    .line 195
    invoke-virtual {v3, v8}, Landroid/app/Notification$Builder;->setRemoteInputHistory([Ljava/lang/CharSequence;)Landroid/app/Notification$Builder;

    .line 196
    iget-object v3, v1, Landroidx/core/app/x;->s:Landroid/widget/RemoteViews;

    if-eqz v3, :cond_12

    .line 197
    iget-object v4, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    check-cast v4, Landroid/app/Notification$Builder;

    .line 198
    invoke-virtual {v4, v3}, Landroid/app/Notification$Builder;->setCustomContentView(Landroid/widget/RemoteViews;)Landroid/app/Notification$Builder;

    .line 199
    :cond_12
    iget-object v3, v1, Landroidx/core/app/x;->t:Landroid/widget/RemoteViews;

    if-eqz v3, :cond_13

    .line 200
    iget-object v4, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    check-cast v4, Landroid/app/Notification$Builder;

    .line 201
    invoke-virtual {v4, v3}, Landroid/app/Notification$Builder;->setCustomBigContentView(Landroid/widget/RemoteViews;)Landroid/app/Notification$Builder;

    .line 202
    :cond_13
    iget-object v3, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    check-cast v3, Landroid/app/Notification$Builder;

    const/4 v12, 0x0

    .line 203
    invoke-virtual {v3, v12}, Landroid/app/Notification$Builder;->setBadgeIconType(I)Landroid/app/Notification$Builder;

    .line 204
    iget-object v3, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    check-cast v3, Landroid/app/Notification$Builder;

    .line 205
    invoke-virtual {v3, v8}, Landroid/app/Notification$Builder;->setSettingsText(Ljava/lang/CharSequence;)Landroid/app/Notification$Builder;

    .line 206
    iget-object v3, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    check-cast v3, Landroid/app/Notification$Builder;

    .line 207
    invoke-virtual {v3, v8}, Landroid/app/Notification$Builder;->setShortcutId(Ljava/lang/String;)Landroid/app/Notification$Builder;

    .line 208
    iget-object v3, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    check-cast v3, Landroid/app/Notification$Builder;

    iget-wide v4, v1, Landroidx/core/app/x;->v:J

    .line 209
    invoke-virtual {v3, v4, v5}, Landroid/app/Notification$Builder;->setTimeoutAfter(J)Landroid/app/Notification$Builder;

    .line 210
    iget-object v3, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    check-cast v3, Landroid/app/Notification$Builder;

    iget v4, v1, Landroidx/core/app/x;->w:I

    .line 211
    invoke-virtual {v3, v4}, Landroid/app/Notification$Builder;->setGroupAlertBehavior(I)Landroid/app/Notification$Builder;

    .line 212
    iget-object v3, v1, Landroidx/core/app/x;->u:Ljava/lang/String;

    invoke-static {v3}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v3

    if-nez v3, :cond_14

    .line 213
    iget-object v3, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    check-cast v3, Landroid/app/Notification$Builder;

    invoke-virtual {v3, v8}, Landroid/app/Notification$Builder;->setSound(Landroid/net/Uri;)Landroid/app/Notification$Builder;

    move-result-object v3

    const/4 v12, 0x0

    .line 214
    invoke-virtual {v3, v12}, Landroid/app/Notification$Builder;->setDefaults(I)Landroid/app/Notification$Builder;

    move-result-object v3

    .line 215
    invoke-virtual {v3, v12, v12, v12}, Landroid/app/Notification$Builder;->setLights(III)Landroid/app/Notification$Builder;

    move-result-object v3

    .line 216
    invoke-virtual {v3, v8}, Landroid/app/Notification$Builder;->setVibrate([J)Landroid/app/Notification$Builder;

    .line 217
    :cond_14
    iget-object v3, v1, Landroidx/core/app/x;->c:Ljava/util/ArrayList;

    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v3

    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-nez v4, :cond_16

    .line 218
    iget-object v3, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    check-cast v3, Landroid/app/Notification$Builder;

    iget-boolean v1, v1, Landroidx/core/app/x;->x:Z

    .line 219
    invoke-virtual {v3, v1}, Landroid/app/Notification$Builder;->setAllowSystemGeneratedContextualActions(Z)Landroid/app/Notification$Builder;

    .line 220
    iget-object v1, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    check-cast v1, Landroid/app/Notification$Builder;

    .line 221
    invoke-virtual {v1, v8}, Landroid/app/Notification$Builder;->setBubbleMetadata(Landroid/app/Notification$BubbleMetadata;)Landroid/app/Notification$Builder;

    const/16 v1, 0x24

    if-lt v2, v1, :cond_15

    .line 222
    iget-object v0, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    check-cast v0, Landroid/app/Notification$Builder;

    invoke-static {v0}, Landroidx/core/app/g0;->a(Landroid/app/Notification$Builder;)V

    :cond_15
    return-void

    .line 223
    :cond_16
    invoke-static {v3}, Lf2/m0;->e(Ljava/util/Iterator;)Ljava/lang/ClassCastException;

    move-result-object v0

    .line 224
    throw v0
.end method

.method public constructor <init>(Landroidx/lifecycle/h1;Landroidx/lifecycle/e1;Lp7/c;)V
    .locals 1

    const/16 v0, 0x18

    iput v0, p0, Lcom/google/firebase/messaging/w;->d:I

    const-string v0, "store"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "factory"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "defaultExtras"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 18
    iput-object p2, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 19
    iput-object p3, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 20
    new-instance p1, Lr7/c;

    .line 21
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 22
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lc1/b0;)V
    .locals 2

    const/4 v0, 0x5

    iput v0, p0, Lcom/google/firebase/messaging/w;->d:I

    .line 413
    new-instance v0, Laq/a;

    const/16 v1, 0x8

    invoke-direct {v0, p1, v1}, Laq/a;-><init>(Ljava/lang/Object;I)V

    .line 414
    invoke-direct {p0, v0}, Lcom/google/firebase/messaging/w;-><init>(Lc1/q;)V

    return-void
.end method

.method public constructor <init>(Lc1/q;)V
    .locals 1

    const/4 v0, 0x5

    iput v0, p0, Lcom/google/firebase/messaging/w;->d:I

    .line 412
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/u;)V
    .locals 1

    const/4 v0, 0x7

    iput v0, p0, Lcom/google/firebase/messaging/w;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    iput-object v0, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    new-instance v0, Ljava/util/HashMap;

    .line 4
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    iput-object v0, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    iput-object p1, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    iput-object p2, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lh0/i0;Lz/a;Lu/g0;Lc2/k;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Lcom/google/firebase/messaging/w;->d:I

    const-string v0, "cameraRepository"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "cameraCoordinator"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "useCaseConfigFactory"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "streamSpecsCalculator"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 229
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 230
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 231
    iput-object p2, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 232
    iput-object p3, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 233
    iput-object p4, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lh0/y0;Landroid/util/Size;Landroid/hardware/camera2/CameraCharacteristics;Z)V
    .locals 18

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    const/16 v2, 0xb

    iput v2, v0, Lcom/google/firebase/messaging/w;->d:I

    .line 264
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 265
    invoke-static {}, Llp/k1;->a()V

    .line 266
    iput-object v1, v0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 267
    sget-object v2, Lh0/o2;->S0:Lh0/g;

    const/4 v8, 0x0

    .line 268
    invoke-interface {v1, v2, v8}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    .line 269
    check-cast v2, Lu/c0;

    if-eqz v2, :cond_c

    .line 270
    new-instance v3, Lb0/n1;

    invoke-direct {v3}, Lb0/n1;-><init>()V

    .line 271
    invoke-virtual {v2, v1, v3}, Lu/c0;->a(Lh0/o2;Lb0/n1;)V

    .line 272
    invoke-virtual {v3}, Lb0/n1;->j()Lh0/o0;

    .line 273
    new-instance v9, Lgw0/c;

    const/16 v2, 0xf

    const/4 v10, 0x0

    .line 274
    invoke-direct {v9, v2, v10}, Lgw0/c;-><init>(IZ)V

    .line 275
    iput-object v9, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 276
    new-instance v11, Lcom/google/android/gms/internal/measurement/i4;

    .line 277
    invoke-static {}, Llp/hb;->c()Lj0/f;

    move-result-object v2

    .line 278
    sget-object v3, Ll0/h;->f1:Lh0/g;

    invoke-interface {v1, v3, v2}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/util/concurrent/Executor;

    .line 279
    invoke-static {v2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    move-object/from16 v3, p3

    .line 280
    invoke-direct {v11, v2, v3}, Lcom/google/android/gms/internal/measurement/i4;-><init>(Ljava/util/concurrent/Executor;Landroid/hardware/camera2/CameraCharacteristics;)V

    iput-object v11, v0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 281
    new-instance v4, Ljava/util/ArrayList;

    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 282
    sget-object v2, Lh0/z0;->D0:Lh0/g;

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-interface {v1, v2, v3}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Integer;

    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    move-result v2

    const/16 v12, 0x100

    const/16 v13, 0x20

    if-eqz v2, :cond_0

    .line 283
    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-virtual {v4, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 284
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-virtual {v4, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    .line 285
    :cond_0
    sget-object v2, Lh0/y0;->g:Lh0/g;

    invoke-interface {v1, v2, v8}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Integer;

    if-eqz v2, :cond_1

    .line 286
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    move-result v2

    goto :goto_0

    .line 287
    :cond_1
    sget-object v2, Lh0/z0;->C0:Lh0/g;

    invoke-interface {v1, v2, v8}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Integer;

    if-eqz v2, :cond_2

    .line 288
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    move-result v3

    const/16 v5, 0x1005

    if-ne v3, v5, :cond_2

    move v2, v5

    goto :goto_0

    :cond_2
    if-eqz v2, :cond_3

    .line 289
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    move-result v2

    if-ne v2, v13, :cond_3

    move v2, v13

    goto :goto_0

    :cond_3
    move v2, v12

    .line 290
    :goto_0
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-virtual {v4, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 291
    :goto_1
    invoke-virtual {v1}, Lh0/y0;->l()I

    move-result v3

    .line 292
    sget-object v2, Lh0/y0;->i:Lh0/g;

    invoke-interface {v1, v2, v8}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    if-nez v1, :cond_b

    .line 293
    new-instance v1, Lg0/a;

    new-instance v6, Lp0/d;

    .line 294
    invoke-direct {v6}, Lp0/d;-><init>()V

    .line 295
    new-instance v7, Lp0/d;

    .line 296
    invoke-direct {v7}, Lp0/d;-><init>()V

    move-object/from16 v2, p2

    move/from16 v5, p4

    .line 297
    invoke-direct/range {v1 .. v7}, Lg0/a;-><init>(Landroid/util/Size;ILjava/util/ArrayList;ZLp0/d;Lp0/d;)V

    .line 298
    iput-object v1, v0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 299
    iget-object v0, v9, Lgw0/c;->g:Ljava/lang/Object;

    check-cast v0, Lg0/a;

    const/4 v5, 0x1

    if-nez v0, :cond_4

    iget-object v0, v9, Lgw0/c;->e:Ljava/lang/Object;

    check-cast v0, Lb0/n1;

    if-nez v0, :cond_4

    move v0, v5

    goto :goto_2

    :cond_4
    move v0, v10

    :goto_2
    const-string v14, "CaptureNode does not support recreation yet."

    invoke-static {v14, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 300
    iput-object v1, v9, Lgw0/c;->g:Ljava/lang/Object;

    .line 301
    new-instance v0, Lb0/e1;

    invoke-direct {v0, v9, v5}, Lb0/e1;-><init>(Ljava/lang/Object;I)V

    .line 302
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    move-result v4

    if-le v4, v5, :cond_5

    move v4, v5

    goto :goto_3

    :cond_5
    move v4, v10

    :goto_3
    const/4 v14, 0x2

    const/4 v15, 0x4

    if-nez p4, :cond_7

    if-eqz v4, :cond_6

    .line 303
    new-instance v8, Lb0/f1;

    move/from16 v16, v10

    invoke-virtual {v2}, Landroid/util/Size;->getWidth()I

    move-result v10

    move/from16 p0, v5

    .line 304
    invoke-virtual {v2}, Landroid/util/Size;->getHeight()I

    move-result v5

    invoke-direct {v8, v10, v5, v12, v15}, Lb0/f1;-><init>(IIII)V

    .line 305
    new-array v5, v14, [Lh0/m;

    aput-object v0, v5, v16

    iget-object v10, v8, Lb0/f1;->e:Lb0/e1;

    aput-object v10, v5, p0

    .line 306
    invoke-static {v5}, Lkp/x9;->b([Lh0/m;)Lh0/m;

    .line 307
    new-instance v5, Lb0/f1;

    .line 308
    invoke-virtual {v2}, Landroid/util/Size;->getWidth()I

    move-result v10

    invoke-virtual {v2}, Landroid/util/Size;->getHeight()I

    move-result v12

    invoke-direct {v5, v10, v12, v13, v15}, Lb0/f1;-><init>(IIII)V

    .line 309
    new-array v10, v14, [Lh0/m;

    aput-object v0, v10, v16

    iget-object v0, v5, Lb0/f1;->e:Lb0/e1;

    aput-object v0, v10, p0

    .line 310
    invoke-static {v10}, Lkp/x9;->b([Lh0/m;)Lh0/m;

    goto :goto_4

    :cond_6
    move/from16 p0, v5

    move/from16 v16, v10

    .line 311
    new-instance v5, Lb0/f1;

    invoke-virtual {v2}, Landroid/util/Size;->getWidth()I

    move-result v10

    .line 312
    invoke-virtual {v2}, Landroid/util/Size;->getHeight()I

    move-result v12

    invoke-direct {v5, v10, v12, v3, v15}, Lb0/f1;-><init>(IIII)V

    .line 313
    new-array v10, v14, [Lh0/m;

    aput-object v0, v10, v16

    iget-object v0, v5, Lb0/f1;->e:Lb0/e1;

    aput-object v0, v10, p0

    .line 314
    invoke-static {v10}, Lkp/x9;->b([Lh0/m;)Lh0/m;

    move-object/from16 v17, v8

    move-object v8, v5

    move-object/from16 v5, v17

    .line 315
    :goto_4
    new-instance v0, Lb0/o1;

    move/from16 v10, p0

    invoke-direct {v0, v9, v10}, Lb0/o1;-><init>(Lgw0/c;I)V

    goto :goto_5

    :cond_7
    move/from16 v16, v10

    move v10, v5

    .line 316
    new-instance v0, Lbu/c;

    .line 317
    invoke-virtual {v2}, Landroid/util/Size;->getWidth()I

    move-result v5

    invoke-virtual {v2}, Landroid/util/Size;->getHeight()I

    move-result v12

    .line 318
    invoke-static {v5, v12, v3, v15}, Ljp/u1;->e(IIII)Lcom/google/android/gms/internal/measurement/i4;

    move-result-object v5

    const/16 v12, 0x16

    .line 319
    invoke-direct {v0, v5, v12}, Lbu/c;-><init>(Ljava/lang/Object;I)V

    .line 320
    new-instance v5, Lb0/o1;

    invoke-direct {v5, v9, v14}, Lb0/o1;-><init>(Lgw0/c;I)V

    move-object/from16 v17, v8

    move-object v8, v0

    move-object v0, v5

    move-object/from16 v5, v17

    .line 321
    :goto_5
    invoke-interface {v8}, Lh0/c1;->getSurface()Landroid/view/Surface;

    move-result-object v12

    invoke-static {v12}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 322
    iget-object v13, v1, Lg0/a;->a:Lb0/u1;

    if-nez v13, :cond_8

    move v13, v10

    goto :goto_6

    :cond_8
    move/from16 v13, v16

    :goto_6
    const-string v14, "The surface is already set."

    invoke-static {v14, v13}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 323
    new-instance v13, Lb0/u1;

    invoke-direct {v13, v12, v2, v3}, Lb0/u1;-><init>(Landroid/view/Surface;Landroid/util/Size;I)V

    iput-object v13, v1, Lg0/a;->a:Lb0/u1;

    .line 324
    new-instance v12, Lb0/n1;

    invoke-direct {v12, v8}, Lb0/n1;-><init>(Lh0/c1;)V

    iput-object v12, v9, Lgw0/c;->e:Ljava/lang/Object;

    .line 325
    new-instance v12, La8/t;

    const/16 v13, 0x1d

    invoke-direct {v12, v9, v13}, La8/t;-><init>(Ljava/lang/Object;I)V

    .line 326
    invoke-static {}, Llp/hb;->d()Lj0/c;

    move-result-object v14

    .line 327
    invoke-interface {v8, v12, v14}, Lh0/c1;->g(Lh0/b1;Ljava/util/concurrent/Executor;)V

    if-eqz v4, :cond_a

    if-eqz v5, :cond_a

    .line 328
    invoke-virtual {v5}, Lb0/f1;->getSurface()Landroid/view/Surface;

    move-result-object v4

    .line 329
    iget-object v8, v1, Lg0/a;->b:Lb0/u1;

    if-nez v8, :cond_9

    goto :goto_7

    :cond_9
    move/from16 v10, v16

    :goto_7
    const-string v8, "The secondary surface is already set."

    invoke-static {v8, v10}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 330
    new-instance v8, Lb0/u1;

    invoke-direct {v8, v4, v2, v3}, Lb0/u1;-><init>(Landroid/view/Surface;Landroid/util/Size;I)V

    iput-object v8, v1, Lg0/a;->b:Lb0/u1;

    .line 331
    new-instance v1, Lb0/n1;

    invoke-direct {v1, v5}, Lb0/n1;-><init>(Lh0/c1;)V

    iput-object v1, v9, Lgw0/c;->f:Ljava/lang/Object;

    .line 332
    new-instance v1, La8/t;

    invoke-direct {v1, v9, v13}, La8/t;-><init>(Ljava/lang/Object;I)V

    .line 333
    invoke-static {}, Llp/hb;->d()Lj0/c;

    move-result-object v2

    .line 334
    invoke-virtual {v5, v1, v2}, Lb0/f1;->g(Lh0/b1;Ljava/util/concurrent/Executor;)V

    .line 335
    :cond_a
    iput-object v0, v6, Lp0/d;->b:Ljava/lang/Object;

    .line 336
    new-instance v0, Lg0/c;

    move/from16 v1, v16

    invoke-direct {v0, v9, v1}, Lg0/c;-><init>(Ljava/lang/Object;I)V

    .line 337
    iput-object v0, v7, Lp0/d;->b:Ljava/lang/Object;

    .line 338
    iget-object v0, v11, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    check-cast v0, Ld01/x;

    .line 339
    const-class v1, Landroidx/camera/core/internal/compat/quirk/IncorrectJpegMetadataQuirk;

    invoke-virtual {v0, v1}, Ld01/x;->l(Ljava/lang/Class;)Lh0/p1;

    move-result-object v0

    check-cast v0, Landroidx/camera/core/internal/compat/quirk/IncorrectJpegMetadataQuirk;

    return-void

    .line 340
    :cond_b
    new-instance v0, Ljava/lang/ClassCastException;

    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    throw v0

    .line 341
    :cond_c
    new-instance v0, Ljava/lang/IllegalStateException;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Implementation is missing option unpacker for "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 342
    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v3

    .line 343
    sget-object v4, Ll0/k;->g1:Lh0/g;

    invoke-interface {v1, v4, v3}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    .line 344
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public constructor <init>(Lh8/e1;[Z)V
    .locals 1

    const/16 v0, 0xd

    iput v0, p0, Lcom/google/firebase/messaging/w;->d:I

    .line 415
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 416
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 417
    iput-object p2, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 418
    iget p1, p1, Lh8/e1;->a:I

    new-array p2, p1, [Z

    iput-object p2, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 419
    new-array p1, p1, [Z

    iput-object p1, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p5, p0, Lcom/google/firebase/messaging/w;->d:I

    iput-object p1, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    iput-object p2, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    iput-object p3, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    iput-object p4, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Ljava/security/Signature;)V
    .locals 1

    const/16 v0, 0x19

    iput v0, p0, Lcom/google/firebase/messaging/w;->d:I

    .line 387
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 388
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    const/4 p1, 0x0

    .line 389
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 390
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 391
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/util/List;)V
    .locals 9

    const/16 v0, 0x1d

    iput v0, p0, Lcom/google/firebase/messaging/w;->d:I

    .line 50
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 51
    new-instance v0, Lw7/p;

    invoke-direct {v0}, Lw7/p;-><init>()V

    iput-object v0, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 52
    new-instance v0, Lw7/p;

    invoke-direct {v0}, Lw7/p;-><init>()V

    iput-object v0, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 53
    new-instance v0, Lt9/a;

    invoke-direct {v0}, Lt9/a;-><init>()V

    iput-object v0, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 54
    new-instance p0, Ljava/lang/String;

    const/4 v1, 0x0

    invoke-interface {p1, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [B

    sget-object v2, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    invoke-direct {p0, p1, v2}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    .line 55
    invoke-virtual {p0}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object p0

    sget-object p1, Lw7/w;->a:Ljava/lang/String;

    .line 56
    const-string p1, "\\r?\\n"

    const/4 v2, -0x1

    invoke-virtual {p0, p1, v2}, Ljava/lang/String;->split(Ljava/lang/String;I)[Ljava/lang/String;

    move-result-object p0

    .line 57
    array-length p1, p0

    move v3, v1

    :goto_0
    if-ge v3, p1, :cond_2

    aget-object v4, p0, v3

    .line 58
    const-string v5, "palette: "

    invoke-virtual {v4, v5}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v5

    if-eqz v5, :cond_0

    const/16 v5, 0x9

    .line 59
    invoke-virtual {v4, v5}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object v4

    const-string v5, ","

    .line 60
    invoke-virtual {v4, v5, v2}, Ljava/lang/String;->split(Ljava/lang/String;I)[Ljava/lang/String;

    move-result-object v4

    .line 61
    array-length v5, v4

    new-array v5, v5, [I

    iput-object v5, v0, Lt9/a;->d:[I

    move v5, v1

    .line 62
    :goto_1
    array-length v6, v4

    if-ge v5, v6, :cond_1

    .line 63
    iget-object v6, v0, Lt9/a;->d:[I

    aget-object v7, v4, v5

    invoke-virtual {v7}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object v7

    const/16 v8, 0x10

    .line 64
    :try_start_0
    invoke-static {v7, v8}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;I)I

    move-result v7
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_2

    :catch_0
    move v7, v1

    .line 65
    :goto_2
    aput v7, v6, v5

    add-int/lit8 v5, v5, 0x1

    goto :goto_1

    .line 66
    :cond_0
    const-string v5, "size: "

    invoke-virtual {v4, v5}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v5

    if-eqz v5, :cond_1

    const/4 v5, 0x6

    .line 67
    invoke-virtual {v4, v5}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v4}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object v4

    const-string v5, "x"

    .line 68
    invoke-virtual {v4, v5, v2}, Ljava/lang/String;->split(Ljava/lang/String;I)[Ljava/lang/String;

    move-result-object v4

    .line 69
    array-length v5, v4

    const/4 v6, 0x2

    if-ne v5, v6, :cond_1

    .line 70
    :try_start_1
    aget-object v5, v4, v1

    invoke-static {v5}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    move-result v5

    iput v5, v0, Lt9/a;->e:I

    const/4 v5, 0x1

    .line 71
    aget-object v4, v4, v5

    invoke-static {v4}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    move-result v4

    iput v4, v0, Lt9/a;->f:I

    .line 72
    iput-boolean v5, v0, Lt9/a;->b:Z
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_1

    goto :goto_3

    :catch_1
    move-exception v4

    .line 73
    const-string v5, "VobsubParser"

    const-string v6, "Parsing IDX failed"

    invoke-static {v5, v6, v4}, Lw7/a;->z(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    :cond_1
    :goto_3
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_2
    return-void
.end method

.method public constructor <init>(Ljavax/crypto/Cipher;)V
    .locals 1

    const/16 v0, 0x19

    iput v0, p0, Lcom/google/firebase/messaging/w;->d:I

    .line 392
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 393
    iput-object v0, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 394
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 395
    iput-object v0, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 396
    iput-object v0, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljavax/crypto/Mac;)V
    .locals 1

    const/16 v0, 0x19

    iput v0, p0, Lcom/google/firebase/messaging/w;->d:I

    .line 397
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 398
    iput-object v0, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 399
    iput-object v0, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 400
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 401
    iput-object v0, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lm6/w;Ljava/util/List;)V
    .locals 1

    const/16 v0, 0x14

    iput v0, p0, Lcom/google/firebase/messaging/w;->d:I

    .line 407
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 408
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 409
    invoke-static {}, Lez0/d;->a()Lez0/c;

    move-result-object p1

    iput-object p1, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 410
    invoke-static {}, Lvy0/e0;->b()Lvy0/r;

    move-result-object p1

    iput-object p1, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 411
    check-cast p2, Ljava/lang/Iterable;

    invoke-static {p2}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object p1

    iput-object p1, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lp3/a0;)V
    .locals 1

    const/16 v0, 0x17

    iput v0, p0, Lcom/google/firebase/messaging/w;->d:I

    .line 37
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 38
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 39
    sget-object p1, Lp3/y;->d:Lp3/y;

    iput-object p1, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lqz0/a;)V
    .locals 1

    const/16 v0, 0x8

    iput v0, p0, Lcom/google/firebase/messaging/w;->d:I

    .line 23
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 24
    const-string v0, ""

    iput-object v0, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 25
    iput-object v0, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 26
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 27
    invoke-interface {p1}, Lqz0/a;->getDescriptor()Lsz0/g;

    move-result-object p1

    invoke-interface {p1}, Lsz0/g;->h()Ljava/lang/String;

    move-result-object p1

    iput-object p1, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Ll71/w;Ll71/z;Ljava/util/ArrayList;Ll71/a;)V
    .locals 7

    const/16 v0, 0x10

    iput v0, p0, Lcom/google/firebase/messaging/w;->d:I

    .line 28
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 29
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;

    .line 30
    invoke-static {p4}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    move-result-object v5

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object v6, p5

    .line 31
    invoke-direct/range {v1 .. v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;-><init>(Lk71/d;Ll71/w;Ll71/z;Ljava/util/Set;Ll71/a;)V

    iput-object v1, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 32
    iget-object p1, v3, Ll71/w;->b:Lu61/b;

    .line 33
    new-instance p2, Ljava/lang/StringBuilder;

    const-string p3, "init() isClosingWindowsSupported = true, "

    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-static {p1, p2}, Lo71/a;->a(Lo71/a;Ljava/lang/String;)V

    .line 34
    iput-object v1, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 35
    iput-object v1, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 36
    iput-object v1, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lvy0/b0;La3/f;Lk31/t;)V
    .locals 2

    const/16 v0, 0x15

    iput v0, p0, Lcom/google/firebase/messaging/w;->d:I

    .line 10
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 11
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 12
    iput-object p3, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    const/4 p3, 0x0

    const/4 v0, 0x6

    const v1, 0x7fffffff

    .line 13
    invoke-static {v1, v0, p3}, Llp/jf;->a(IILxy0/a;)Lxy0/j;

    move-result-object p3

    iput-object p3, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 14
    new-instance p3, Lhu/q;

    const/16 v0, 0x14

    const/4 v1, 0x0

    invoke-direct {p3, v1, v0}, Lhu/q;-><init>(BI)V

    iput-object p3, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 15
    invoke-interface {p1}, Lvy0/b0;->getCoroutineContext()Lpx0/g;

    move-result-object p1

    sget-object p3, Lvy0/h1;->d:Lvy0/h1;

    invoke-interface {p1, p3}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    move-result-object p1

    check-cast p1, Lvy0/i1;

    if-eqz p1, :cond_0

    new-instance p3, Lb1/e;

    const/16 v0, 0x8

    invoke-direct {p3, v0, p2, p0}, Lb1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-interface {p1, p3}, Lvy0/i1;->E(Lay0/k;)Lvy0/r0;

    :cond_0
    return-void
.end method

.method public constructor <init>(Lwe0/a;)V
    .locals 1

    const/16 v0, 0x13

    iput v0, p0, Lcom/google/firebase/messaging/w;->d:I

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 6
    invoke-static {}, Lez0/d;->a()Lez0/c;

    move-result-object p1

    iput-object p1, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 7
    sget-object p1, Lne0/d;->a:Lne0/d;

    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    iput-object p1, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 8
    new-instance v0, Lyy0/k1;

    invoke-direct {v0, p1}, Lyy0/k1;-><init>(Lyy0/n1;)V

    .line 9
    iput-object v0, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    return-void
.end method

.method public static declared-synchronized k()Lcom/google/firebase/messaging/w;
    .locals 3

    .line 1
    const-class v0, Lcom/google/firebase/messaging/w;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    sget-object v1, Lcom/google/firebase/messaging/w;->i:Lcom/google/firebase/messaging/w;

    .line 5
    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    new-instance v1, Lcom/google/firebase/messaging/w;

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    invoke-direct {v1, v2}, Lcom/google/firebase/messaging/w;-><init>(I)V

    .line 12
    .line 13
    .line 14
    sput-object v1, Lcom/google/firebase/messaging/w;->i:Lcom/google/firebase/messaging/w;

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :catchall_0
    move-exception v1

    .line 18
    goto :goto_1

    .line 19
    :cond_0
    :goto_0
    sget-object v1, Lcom/google/firebase/messaging/w;->i:Lcom/google/firebase/messaging/w;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 20
    .line 21
    monitor-exit v0

    .line 22
    return-object v1

    .line 23
    :goto_1
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 24
    throw v1
.end method


# virtual methods
.method public A(Ljava/lang/String;)Z
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/HashMap;

    .line 4
    .line 5
    invoke-virtual {v0, p1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Lcom/google/firebase/messaging/w;

    .line 16
    .line 17
    if-eqz p0, :cond_1

    .line 18
    .line 19
    invoke-virtual {p0, p1}, Lcom/google/firebase/messaging/w;->A(Ljava/lang/String;)Z

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0

    .line 24
    :cond_1
    const/4 p0, 0x0

    .line 25
    return p0
.end method

.method public B(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/o;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/HashMap;

    .line 4
    .line 5
    invoke-virtual {v0, p1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-nez v1, :cond_1

    .line 10
    .line 11
    iget-object v1, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v1, Lcom/google/firebase/messaging/w;

    .line 14
    .line 15
    if-eqz v1, :cond_1

    .line 16
    .line 17
    invoke-virtual {v1, p1}, Lcom/google/firebase/messaging/w;->A(Ljava/lang/String;)Z

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    if-nez v2, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    invoke-virtual {v1, p1, p2}, Lcom/google/firebase/messaging/w;->B(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/o;)V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    :cond_1
    :goto_0
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast p0, Ljava/util/HashMap;

    .line 31
    .line 32
    invoke-virtual {p0, p1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    if-eqz p0, :cond_2

    .line 37
    .line 38
    return-void

    .line 39
    :cond_2
    if-nez p2, :cond_3

    .line 40
    .line 41
    invoke-virtual {v0, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    return-void

    .line 45
    :cond_3
    invoke-virtual {v0, p1, p2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    return-void
.end method

.method public C(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/o;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/HashMap;

    .line 4
    .line 5
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Ljava/util/HashMap;

    .line 8
    .line 9
    invoke-virtual {p0, p1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    return-void

    .line 16
    :cond_0
    if-nez p2, :cond_1

    .line 17
    .line 18
    invoke-virtual {v0, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :cond_1
    invoke-virtual {v0, p1, p2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    return-void
.end method

.method public D(JLc1/p;Lc1/p;Lc1/p;)Lc1/p;
    .locals 14

    .line 1
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lc1/p;

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    invoke-virtual/range {p5 .. p5}, Lc1/p;->c()Lc1/p;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iput-object v0, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 12
    .line 13
    :cond_0
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v0, Lc1/p;

    .line 16
    .line 17
    const/4 v1, 0x0

    .line 18
    const-string v2, "velocityVector"

    .line 19
    .line 20
    if-eqz v0, :cond_4

    .line 21
    .line 22
    invoke-virtual {v0}, Lc1/p;->b()I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    const/4 v3, 0x0

    .line 27
    :goto_0
    if-ge v3, v0, :cond_2

    .line 28
    .line 29
    iget-object v4, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v4, Lc1/p;

    .line 32
    .line 33
    if-eqz v4, :cond_1

    .line 34
    .line 35
    iget-object v5, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v5, Lc1/q;

    .line 38
    .line 39
    invoke-interface {v5, v3}, Lc1/q;->get(I)Lc1/b0;

    .line 40
    .line 41
    .line 42
    move-result-object v6

    .line 43
    move-object/from16 v5, p3

    .line 44
    .line 45
    invoke-virtual {v5, v3}, Lc1/p;->a(I)F

    .line 46
    .line 47
    .line 48
    move-result v9

    .line 49
    move-object/from16 v12, p4

    .line 50
    .line 51
    invoke-virtual {v12, v3}, Lc1/p;->a(I)F

    .line 52
    .line 53
    .line 54
    move-result v10

    .line 55
    move-object/from16 v13, p5

    .line 56
    .line 57
    invoke-virtual {v13, v3}, Lc1/p;->a(I)F

    .line 58
    .line 59
    .line 60
    move-result v11

    .line 61
    move-wide v7, p1

    .line 62
    invoke-interface/range {v6 .. v11}, Lc1/b0;->d(JFFF)F

    .line 63
    .line 64
    .line 65
    move-result v6

    .line 66
    invoke-virtual {v4, v3, v6}, Lc1/p;->e(IF)V

    .line 67
    .line 68
    .line 69
    add-int/lit8 v3, v3, 0x1

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_1
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    throw v1

    .line 76
    :cond_2
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast p0, Lc1/p;

    .line 79
    .line 80
    if-eqz p0, :cond_3

    .line 81
    .line 82
    return-object p0

    .line 83
    :cond_3
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    throw v1

    .line 87
    :cond_4
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    throw v1
.end method

.method public E(Ljava/lang/String;)Lcom/google/android/gms/internal/measurement/o;
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/HashMap;

    .line 4
    .line 5
    invoke-virtual {v0, p1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    invoke-virtual {v0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Lcom/google/android/gms/internal/measurement/o;

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_0
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Lcom/google/firebase/messaging/w;

    .line 21
    .line 22
    if-eqz p0, :cond_1

    .line 23
    .line 24
    invoke-virtual {p0, p1}, Lcom/google/firebase/messaging/w;->E(Ljava/lang/String;)Lcom/google/android/gms/internal/measurement/o;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 30
    .line 31
    const-string v0, " is not defined"

    .line 32
    .line 33
    invoke-static {p1, v0}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    throw p0
.end method

.method public P(Lc1/p;Lc1/p;Lc1/p;)Lc1/p;
    .locals 9

    .line 1
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lc1/p;

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p3}, Lc1/p;->c()Lc1/p;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iput-object v0, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 12
    .line 13
    :cond_0
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v0, Lc1/p;

    .line 16
    .line 17
    const/4 v1, 0x0

    .line 18
    const-string v2, "endVelocityVector"

    .line 19
    .line 20
    if-eqz v0, :cond_4

    .line 21
    .line 22
    invoke-virtual {v0}, Lc1/p;->b()I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    const/4 v3, 0x0

    .line 27
    :goto_0
    if-ge v3, v0, :cond_2

    .line 28
    .line 29
    iget-object v4, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v4, Lc1/p;

    .line 32
    .line 33
    if-eqz v4, :cond_1

    .line 34
    .line 35
    iget-object v5, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v5, Lc1/q;

    .line 38
    .line 39
    invoke-interface {v5, v3}, Lc1/q;->get(I)Lc1/b0;

    .line 40
    .line 41
    .line 42
    move-result-object v5

    .line 43
    invoke-virtual {p1, v3}, Lc1/p;->a(I)F

    .line 44
    .line 45
    .line 46
    move-result v6

    .line 47
    invoke-virtual {p2, v3}, Lc1/p;->a(I)F

    .line 48
    .line 49
    .line 50
    move-result v7

    .line 51
    invoke-virtual {p3, v3}, Lc1/p;->a(I)F

    .line 52
    .line 53
    .line 54
    move-result v8

    .line 55
    invoke-interface {v5, v6, v7, v8}, Lc1/b0;->b(FFF)F

    .line 56
    .line 57
    .line 58
    move-result v5

    .line 59
    invoke-virtual {v4, v3, v5}, Lc1/p;->e(IF)V

    .line 60
    .line 61
    .line 62
    add-int/lit8 v3, v3, 0x1

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_1
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw v1

    .line 69
    :cond_2
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast p0, Lc1/p;

    .line 72
    .line 73
    if-eqz p0, :cond_3

    .line 74
    .line 75
    return-object p0

    .line 76
    :cond_3
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    throw v1

    .line 80
    :cond_4
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    throw v1
.end method

.method public c(Ljava/lang/String;Ljava/lang/String;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/String;

    .line 4
    .line 5
    invoke-interface {v0}, Ljava/lang/CharSequence;->length()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    const-string v0, "?"

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const-string v0, "&"

    .line 15
    .line 16
    :goto_0
    new-instance v1, Ljava/lang/StringBuilder;

    .line 17
    .line 18
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 19
    .line 20
    .line 21
    iget-object v2, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v2, Ljava/lang/String;

    .line 24
    .line 25
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    const/16 p1, 0x3d

    .line 35
    .line 36
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 47
    .line 48
    return-void
.end method

.method public d()V
    .locals 6

    .line 1
    invoke-static {}, Llp/k1;->a()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast v0, Lgw0/c;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    invoke-static {}, Llp/k1;->a()V

    .line 12
    .line 13
    .line 14
    iget-object v1, v0, Lgw0/c;->g:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v1, Lg0/a;

    .line 17
    .line 18
    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    iget-object v2, v0, Lgw0/c;->e:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v2, Lb0/n1;

    .line 24
    .line 25
    invoke-static {v2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    iget-object v0, v0, Lgw0/c;->f:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v0, Lb0/n1;

    .line 31
    .line 32
    iget-object v3, v1, Lg0/a;->a:Lb0/u1;

    .line 33
    .line 34
    invoke-static {v3}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v3}, Lh0/t0;->a()V

    .line 38
    .line 39
    .line 40
    iget-object v3, v1, Lg0/a;->a:Lb0/u1;

    .line 41
    .line 42
    invoke-static {v3}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    iget-object v3, v3, Lh0/t0;->e:Ly4/k;

    .line 46
    .line 47
    invoke-static {v3}, Lk0/h;->d(Lcom/google/common/util/concurrent/ListenableFuture;)Lcom/google/common/util/concurrent/ListenableFuture;

    .line 48
    .line 49
    .line 50
    move-result-object v3

    .line 51
    new-instance v4, Lg0/d;

    .line 52
    .line 53
    const/4 v5, 0x0

    .line 54
    invoke-direct {v4, v2, v5}, Lg0/d;-><init>(Lb0/n1;I)V

    .line 55
    .line 56
    .line 57
    invoke-static {}, Llp/hb;->d()Lj0/c;

    .line 58
    .line 59
    .line 60
    move-result-object v2

    .line 61
    invoke-interface {v3, v2, v4}, Lcom/google/common/util/concurrent/ListenableFuture;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 62
    .line 63
    .line 64
    iget-object v2, v1, Lg0/a;->c:Lb0/u1;

    .line 65
    .line 66
    if-eqz v2, :cond_0

    .line 67
    .line 68
    invoke-virtual {v2}, Lh0/t0;->a()V

    .line 69
    .line 70
    .line 71
    iget-object v2, v1, Lg0/a;->c:Lb0/u1;

    .line 72
    .line 73
    iget-object v2, v2, Lh0/t0;->e:Ly4/k;

    .line 74
    .line 75
    invoke-static {v2}, Lk0/h;->d(Lcom/google/common/util/concurrent/ListenableFuture;)Lcom/google/common/util/concurrent/ListenableFuture;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    new-instance v3, Lg0/d;

    .line 80
    .line 81
    const/4 v4, 0x1

    .line 82
    const/4 v5, 0x0

    .line 83
    invoke-direct {v3, v5, v4}, Lg0/d;-><init>(Lb0/n1;I)V

    .line 84
    .line 85
    .line 86
    invoke-static {}, Llp/hb;->d()Lj0/c;

    .line 87
    .line 88
    .line 89
    move-result-object v4

    .line 90
    invoke-interface {v2, v4, v3}, Lcom/google/common/util/concurrent/ListenableFuture;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 91
    .line 92
    .line 93
    :cond_0
    iget-object v2, v1, Lg0/a;->f:Ljava/util/ArrayList;

    .line 94
    .line 95
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 96
    .line 97
    .line 98
    move-result v2

    .line 99
    const/4 v3, 0x1

    .line 100
    if-le v2, v3, :cond_1

    .line 101
    .line 102
    iget-object v2, v1, Lg0/a;->b:Lb0/u1;

    .line 103
    .line 104
    if-eqz v2, :cond_1

    .line 105
    .line 106
    invoke-virtual {v2}, Lh0/t0;->a()V

    .line 107
    .line 108
    .line 109
    iget-object v1, v1, Lg0/a;->b:Lb0/u1;

    .line 110
    .line 111
    iget-object v1, v1, Lh0/t0;->e:Ly4/k;

    .line 112
    .line 113
    invoke-static {v1}, Lk0/h;->d(Lcom/google/common/util/concurrent/ListenableFuture;)Lcom/google/common/util/concurrent/ListenableFuture;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    new-instance v2, Lg0/d;

    .line 118
    .line 119
    const/4 v3, 0x2

    .line 120
    invoke-direct {v2, v0, v3}, Lg0/d;-><init>(Lb0/n1;I)V

    .line 121
    .line 122
    .line 123
    invoke-static {}, Llp/hb;->d()Lj0/c;

    .line 124
    .line 125
    .line 126
    move-result-object v0

    .line 127
    invoke-interface {v1, v0, v2}, Lcom/google/common/util/concurrent/ListenableFuture;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 128
    .line 129
    .line 130
    :cond_1
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 131
    .line 132
    check-cast p0, Lcom/google/android/gms/internal/measurement/i4;

    .line 133
    .line 134
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 135
    .line 136
    .line 137
    return-void
.end method

.method public e(Ljava/lang/Object;Ljava/util/ArrayList;Ljava/util/HashSet;)V
    .locals 4

    .line 1
    invoke-virtual {p2, p1}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    invoke-virtual {p3, p1}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-nez v0, :cond_2

    .line 13
    .line 14
    invoke-virtual {p3, p1}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v0, Landroidx/collection/a1;

    .line 20
    .line 21
    invoke-virtual {v0, p1}, Landroidx/collection/a1;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    check-cast v0, Ljava/util/ArrayList;

    .line 26
    .line 27
    if-eqz v0, :cond_1

    .line 28
    .line 29
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    const/4 v2, 0x0

    .line 34
    :goto_0
    if-ge v2, v1, :cond_1

    .line 35
    .line 36
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v3

    .line 40
    invoke-virtual {p0, v3, p2, p3}, Lcom/google/firebase/messaging/w;->e(Ljava/lang/Object;Ljava/util/ArrayList;Ljava/util/HashSet;)V

    .line 41
    .line 42
    .line 43
    add-int/lit8 v2, v2, 0x1

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_1
    invoke-virtual {p3, p1}, Ljava/util/HashSet;->remove(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    invoke-virtual {p2, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    return-void

    .line 53
    :cond_2
    new-instance p0, Ljava/lang/RuntimeException;

    .line 54
    .line 55
    const-string p1, "This graph contains cyclic dependencies"

    .line 56
    .line 57
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw p0
.end method

.method public f(Lp3/k;Z)V
    .locals 8

    .line 1
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lp3/a0;

    .line 4
    .line 5
    iget-object v1, p1, Lp3/k;->a:Ljava/lang/Object;

    .line 6
    .line 7
    move-object v2, v1

    .line 8
    check-cast v2, Ljava/util/Collection;

    .line 9
    .line 10
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 11
    .line 12
    .line 13
    move-result v3

    .line 14
    const/4 v4, 0x0

    .line 15
    move v5, v4

    .line 16
    :goto_0
    if-ge v5, v3, :cond_1

    .line 17
    .line 18
    invoke-interface {v1, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v6

    .line 22
    check-cast v6, Lp3/t;

    .line 23
    .line 24
    invoke-virtual {v6}, Lp3/t;->b()Z

    .line 25
    .line 26
    .line 27
    move-result v6

    .line 28
    if-eqz v6, :cond_0

    .line 29
    .line 30
    invoke-virtual {p0, p1}, Lcom/google/firebase/messaging/w;->s(Lp3/k;)V

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :cond_0
    add-int/lit8 v5, v5, 0x1

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_1
    iget-object v3, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v3, Lt3/y;

    .line 40
    .line 41
    if-eqz v3, :cond_4

    .line 42
    .line 43
    const-wide/16 v5, 0x0

    .line 44
    .line 45
    invoke-interface {v3, v5, v6}, Lt3/y;->R(J)J

    .line 46
    .line 47
    .line 48
    move-result-wide v5

    .line 49
    new-instance v3, Lb1/e;

    .line 50
    .line 51
    const/16 v7, 0x9

    .line 52
    .line 53
    invoke-direct {v3, v7, p0, v0}, Lb1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    invoke-static {p1, v5, v6, v3, v4}, Lp3/s;->i(Lp3/k;JLay0/k;Z)V

    .line 57
    .line 58
    .line 59
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast p0, Lp3/y;

    .line 62
    .line 63
    sget-object v3, Lp3/y;->e:Lp3/y;

    .line 64
    .line 65
    if-ne p0, v3, :cond_3

    .line 66
    .line 67
    if-eqz p2, :cond_2

    .line 68
    .line 69
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 70
    .line 71
    .line 72
    move-result p0

    .line 73
    :goto_1
    if-ge v4, p0, :cond_2

    .line 74
    .line 75
    invoke-interface {v1, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p2

    .line 79
    check-cast p2, Lp3/t;

    .line 80
    .line 81
    invoke-virtual {p2}, Lp3/t;->a()V

    .line 82
    .line 83
    .line 84
    add-int/lit8 v4, v4, 0x1

    .line 85
    .line 86
    goto :goto_1

    .line 87
    :cond_2
    iget-object p0, p1, Lp3/k;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 88
    .line 89
    if-eqz p0, :cond_3

    .line 90
    .line 91
    iget-boolean p1, v0, Lp3/a0;->d:Z

    .line 92
    .line 93
    xor-int/lit8 p1, p1, 0x1

    .line 94
    .line 95
    iput-boolean p1, p0, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    .line 96
    .line 97
    :cond_3
    return-void

    .line 98
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 99
    .line 100
    const-string p1, "layoutCoordinates not set"

    .line 101
    .line 102
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    throw p0
.end method

.method public g([BIILl9/i;Lw7/f;)V
    .locals 45

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p2

    .line 6
    .line 7
    move-object/from16 v3, p5

    .line 8
    .line 9
    iget v4, v0, Lcom/google/firebase/messaging/w;->d:I

    .line 10
    .line 11
    const/4 v5, 0x4

    .line 12
    const/4 v6, 0x3

    .line 13
    const/16 v7, 0x78

    .line 14
    .line 15
    const/16 v8, 0xff

    .line 16
    .line 17
    const/4 v9, 0x0

    .line 18
    const/4 v10, 0x0

    .line 19
    const/4 v11, 0x2

    .line 20
    const/4 v12, 0x1

    .line 21
    packed-switch v4, :pswitch_data_0

    .line 22
    .line 23
    .line 24
    iget-object v4, v0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v4, Lw7/p;

    .line 27
    .line 28
    add-int v13, v2, p3

    .line 29
    .line 30
    invoke-virtual {v4, v13, v1}, Lw7/p;->G(I[B)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v4, v2}, Lw7/p;->I(I)V

    .line 34
    .line 35
    .line 36
    iget-object v1, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v1, Lw7/p;

    .line 39
    .line 40
    iget-object v2, v0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast v2, Lt9/a;

    .line 43
    .line 44
    iget-object v13, v0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v13, Ljava/util/zip/Inflater;

    .line 47
    .line 48
    if-nez v13, :cond_0

    .line 49
    .line 50
    new-instance v13, Ljava/util/zip/Inflater;

    .line 51
    .line 52
    invoke-direct {v13}, Ljava/util/zip/Inflater;-><init>()V

    .line 53
    .line 54
    .line 55
    iput-object v13, v0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 56
    .line 57
    :cond_0
    iget-object v0, v0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast v0, Ljava/util/zip/Inflater;

    .line 60
    .line 61
    sget-object v13, Lw7/w;->a:Ljava/lang/String;

    .line 62
    .line 63
    invoke-virtual {v4}, Lw7/p;->a()I

    .line 64
    .line 65
    .line 66
    move-result v13

    .line 67
    if-lez v13, :cond_1

    .line 68
    .line 69
    iget-object v13, v4, Lw7/p;->a:[B

    .line 70
    .line 71
    iget v14, v4, Lw7/p;->b:I

    .line 72
    .line 73
    aget-byte v13, v13, v14

    .line 74
    .line 75
    and-int/2addr v8, v13

    .line 76
    if-ne v8, v7, :cond_1

    .line 77
    .line 78
    invoke-static {v4, v1, v0}, Lw7/w;->y(Lw7/p;Lw7/p;Ljava/util/zip/Inflater;)Z

    .line 79
    .line 80
    .line 81
    move-result v0

    .line 82
    if-eqz v0, :cond_1

    .line 83
    .line 84
    iget-object v0, v1, Lw7/p;->a:[B

    .line 85
    .line 86
    iget v1, v1, Lw7/p;->c:I

    .line 87
    .line 88
    invoke-virtual {v4, v1, v0}, Lw7/p;->G(I[B)V

    .line 89
    .line 90
    .line 91
    :cond_1
    iput-boolean v9, v2, Lt9/a;->c:Z

    .line 92
    .line 93
    iput-object v10, v2, Lt9/a;->g:Landroid/graphics/Rect;

    .line 94
    .line 95
    const/4 v0, -0x1

    .line 96
    iput v0, v2, Lt9/a;->h:I

    .line 97
    .line 98
    iput v0, v2, Lt9/a;->i:I

    .line 99
    .line 100
    invoke-virtual {v4}, Lw7/p;->a()I

    .line 101
    .line 102
    .line 103
    move-result v1

    .line 104
    if-lt v1, v11, :cond_a

    .line 105
    .line 106
    invoke-virtual {v4}, Lw7/p;->C()I

    .line 107
    .line 108
    .line 109
    move-result v7

    .line 110
    if-eq v7, v1, :cond_2

    .line 111
    .line 112
    goto/16 :goto_3

    .line 113
    .line 114
    :cond_2
    iget-object v1, v2, Lt9/a;->d:[I

    .line 115
    .line 116
    if-eqz v1, :cond_8

    .line 117
    .line 118
    iget-boolean v7, v2, Lt9/a;->b:Z

    .line 119
    .line 120
    if-nez v7, :cond_3

    .line 121
    .line 122
    goto/16 :goto_2

    .line 123
    .line 124
    :cond_3
    invoke-virtual {v4}, Lw7/p;->C()I

    .line 125
    .line 126
    .line 127
    move-result v7

    .line 128
    sub-int/2addr v7, v11

    .line 129
    invoke-virtual {v4, v7}, Lw7/p;->J(I)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v4}, Lw7/p;->C()I

    .line 133
    .line 134
    .line 135
    move-result v7

    .line 136
    iget-object v8, v2, Lt9/a;->a:[I

    .line 137
    .line 138
    :goto_0
    :pswitch_0
    iget v13, v4, Lw7/p;->b:I

    .line 139
    .line 140
    if-ge v13, v7, :cond_8

    .line 141
    .line 142
    invoke-virtual {v4}, Lw7/p;->a()I

    .line 143
    .line 144
    .line 145
    move-result v13

    .line 146
    if-lez v13, :cond_8

    .line 147
    .line 148
    invoke-virtual {v4}, Lw7/p;->w()I

    .line 149
    .line 150
    .line 151
    move-result v13

    .line 152
    packed-switch v13, :pswitch_data_1

    .line 153
    .line 154
    .line 155
    goto/16 :goto_2

    .line 156
    .line 157
    :pswitch_1
    invoke-virtual {v4}, Lw7/p;->a()I

    .line 158
    .line 159
    .line 160
    move-result v13

    .line 161
    if-ge v13, v5, :cond_4

    .line 162
    .line 163
    goto/16 :goto_2

    .line 164
    .line 165
    :cond_4
    invoke-virtual {v4}, Lw7/p;->C()I

    .line 166
    .line 167
    .line 168
    move-result v13

    .line 169
    iput v13, v2, Lt9/a;->h:I

    .line 170
    .line 171
    invoke-virtual {v4}, Lw7/p;->C()I

    .line 172
    .line 173
    .line 174
    move-result v13

    .line 175
    iput v13, v2, Lt9/a;->i:I

    .line 176
    .line 177
    goto :goto_0

    .line 178
    :pswitch_2
    invoke-virtual {v4}, Lw7/p;->a()I

    .line 179
    .line 180
    .line 181
    move-result v13

    .line 182
    const/4 v14, 0x6

    .line 183
    if-ge v13, v14, :cond_5

    .line 184
    .line 185
    goto/16 :goto_2

    .line 186
    .line 187
    :cond_5
    invoke-virtual {v4}, Lw7/p;->w()I

    .line 188
    .line 189
    .line 190
    move-result v13

    .line 191
    invoke-virtual {v4}, Lw7/p;->w()I

    .line 192
    .line 193
    .line 194
    move-result v14

    .line 195
    invoke-virtual {v4}, Lw7/p;->w()I

    .line 196
    .line 197
    .line 198
    move-result v15

    .line 199
    shl-int/2addr v13, v5

    .line 200
    shr-int/lit8 v16, v14, 0x4

    .line 201
    .line 202
    or-int v13, v13, v16

    .line 203
    .line 204
    and-int/lit8 v14, v14, 0xf

    .line 205
    .line 206
    shl-int/lit8 v14, v14, 0x8

    .line 207
    .line 208
    or-int/2addr v14, v15

    .line 209
    invoke-virtual {v4}, Lw7/p;->w()I

    .line 210
    .line 211
    .line 212
    move-result v15

    .line 213
    invoke-virtual {v4}, Lw7/p;->w()I

    .line 214
    .line 215
    .line 216
    move-result v16

    .line 217
    invoke-virtual {v4}, Lw7/p;->w()I

    .line 218
    .line 219
    .line 220
    move-result v17

    .line 221
    shl-int/2addr v15, v5

    .line 222
    shr-int/lit8 v18, v16, 0x4

    .line 223
    .line 224
    or-int v15, v15, v18

    .line 225
    .line 226
    and-int/lit8 v16, v16, 0xf

    .line 227
    .line 228
    shl-int/lit8 v16, v16, 0x8

    .line 229
    .line 230
    or-int v16, v16, v17

    .line 231
    .line 232
    new-instance v10, Landroid/graphics/Rect;

    .line 233
    .line 234
    add-int/2addr v14, v12

    .line 235
    add-int/lit8 v5, v16, 0x1

    .line 236
    .line 237
    invoke-direct {v10, v13, v15, v14, v5}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 238
    .line 239
    .line 240
    iput-object v10, v2, Lt9/a;->g:Landroid/graphics/Rect;

    .line 241
    .line 242
    :goto_1
    const/4 v5, 0x4

    .line 243
    const/4 v10, 0x0

    .line 244
    goto :goto_0

    .line 245
    :pswitch_3
    invoke-virtual {v4}, Lw7/p;->a()I

    .line 246
    .line 247
    .line 248
    move-result v5

    .line 249
    if-lt v5, v11, :cond_8

    .line 250
    .line 251
    iget-boolean v5, v2, Lt9/a;->c:Z

    .line 252
    .line 253
    if-nez v5, :cond_6

    .line 254
    .line 255
    goto :goto_2

    .line 256
    :cond_6
    invoke-virtual {v4}, Lw7/p;->w()I

    .line 257
    .line 258
    .line 259
    move-result v5

    .line 260
    invoke-virtual {v4}, Lw7/p;->w()I

    .line 261
    .line 262
    .line 263
    move-result v10

    .line 264
    aget v13, v8, v6

    .line 265
    .line 266
    shr-int/lit8 v14, v5, 0x4

    .line 267
    .line 268
    invoke-static {v13, v14}, Lt9/a;->c(II)I

    .line 269
    .line 270
    .line 271
    move-result v13

    .line 272
    aput v13, v8, v6

    .line 273
    .line 274
    aget v13, v8, v11

    .line 275
    .line 276
    and-int/lit8 v5, v5, 0xf

    .line 277
    .line 278
    invoke-static {v13, v5}, Lt9/a;->c(II)I

    .line 279
    .line 280
    .line 281
    move-result v5

    .line 282
    aput v5, v8, v11

    .line 283
    .line 284
    aget v5, v8, v12

    .line 285
    .line 286
    shr-int/lit8 v13, v10, 0x4

    .line 287
    .line 288
    invoke-static {v5, v13}, Lt9/a;->c(II)I

    .line 289
    .line 290
    .line 291
    move-result v5

    .line 292
    aput v5, v8, v12

    .line 293
    .line 294
    aget v5, v8, v9

    .line 295
    .line 296
    and-int/lit8 v10, v10, 0xf

    .line 297
    .line 298
    invoke-static {v5, v10}, Lt9/a;->c(II)I

    .line 299
    .line 300
    .line 301
    move-result v5

    .line 302
    aput v5, v8, v9

    .line 303
    .line 304
    goto :goto_1

    .line 305
    :pswitch_4
    invoke-virtual {v4}, Lw7/p;->a()I

    .line 306
    .line 307
    .line 308
    move-result v5

    .line 309
    if-ge v5, v11, :cond_7

    .line 310
    .line 311
    goto :goto_2

    .line 312
    :cond_7
    invoke-virtual {v4}, Lw7/p;->w()I

    .line 313
    .line 314
    .line 315
    move-result v5

    .line 316
    invoke-virtual {v4}, Lw7/p;->w()I

    .line 317
    .line 318
    .line 319
    move-result v10

    .line 320
    shr-int/lit8 v13, v5, 0x4

    .line 321
    .line 322
    invoke-static {v13, v1}, Lt9/a;->a(I[I)I

    .line 323
    .line 324
    .line 325
    move-result v13

    .line 326
    aput v13, v8, v6

    .line 327
    .line 328
    and-int/lit8 v5, v5, 0xf

    .line 329
    .line 330
    invoke-static {v5, v1}, Lt9/a;->a(I[I)I

    .line 331
    .line 332
    .line 333
    move-result v5

    .line 334
    aput v5, v8, v11

    .line 335
    .line 336
    shr-int/lit8 v5, v10, 0x4

    .line 337
    .line 338
    invoke-static {v5, v1}, Lt9/a;->a(I[I)I

    .line 339
    .line 340
    .line 341
    move-result v5

    .line 342
    aput v5, v8, v12

    .line 343
    .line 344
    and-int/lit8 v5, v10, 0xf

    .line 345
    .line 346
    invoke-static {v5, v1}, Lt9/a;->a(I[I)I

    .line 347
    .line 348
    .line 349
    move-result v5

    .line 350
    aput v5, v8, v9

    .line 351
    .line 352
    iput-boolean v12, v2, Lt9/a;->c:Z

    .line 353
    .line 354
    goto :goto_1

    .line 355
    :cond_8
    :goto_2
    iget-object v1, v2, Lt9/a;->d:[I

    .line 356
    .line 357
    if-eqz v1, :cond_a

    .line 358
    .line 359
    iget-boolean v1, v2, Lt9/a;->b:Z

    .line 360
    .line 361
    if-eqz v1, :cond_a

    .line 362
    .line 363
    iget-boolean v1, v2, Lt9/a;->c:Z

    .line 364
    .line 365
    if-eqz v1, :cond_a

    .line 366
    .line 367
    iget-object v1, v2, Lt9/a;->g:Landroid/graphics/Rect;

    .line 368
    .line 369
    if-eqz v1, :cond_a

    .line 370
    .line 371
    iget v5, v2, Lt9/a;->h:I

    .line 372
    .line 373
    if-eq v5, v0, :cond_a

    .line 374
    .line 375
    iget v5, v2, Lt9/a;->i:I

    .line 376
    .line 377
    if-eq v5, v0, :cond_a

    .line 378
    .line 379
    invoke-virtual {v1}, Landroid/graphics/Rect;->width()I

    .line 380
    .line 381
    .line 382
    move-result v0

    .line 383
    if-lt v0, v11, :cond_a

    .line 384
    .line 385
    iget-object v0, v2, Lt9/a;->g:Landroid/graphics/Rect;

    .line 386
    .line 387
    invoke-virtual {v0}, Landroid/graphics/Rect;->height()I

    .line 388
    .line 389
    .line 390
    move-result v0

    .line 391
    if-ge v0, v11, :cond_9

    .line 392
    .line 393
    goto/16 :goto_3

    .line 394
    .line 395
    :cond_9
    iget-object v0, v2, Lt9/a;->g:Landroid/graphics/Rect;

    .line 396
    .line 397
    invoke-virtual {v0}, Landroid/graphics/Rect;->width()I

    .line 398
    .line 399
    .line 400
    move-result v1

    .line 401
    invoke-virtual {v0}, Landroid/graphics/Rect;->height()I

    .line 402
    .line 403
    .line 404
    move-result v5

    .line 405
    mul-int/2addr v5, v1

    .line 406
    new-array v1, v5, [I

    .line 407
    .line 408
    new-instance v5, Lm9/f;

    .line 409
    .line 410
    invoke-direct {v5}, Lm9/f;-><init>()V

    .line 411
    .line 412
    .line 413
    iget v6, v2, Lt9/a;->h:I

    .line 414
    .line 415
    invoke-virtual {v4, v6}, Lw7/p;->I(I)V

    .line 416
    .line 417
    .line 418
    invoke-virtual {v5, v4}, Lm9/f;->p(Lw7/p;)V

    .line 419
    .line 420
    .line 421
    invoke-virtual {v2, v5, v12, v0, v1}, Lt9/a;->b(Lm9/f;ZLandroid/graphics/Rect;[I)V

    .line 422
    .line 423
    .line 424
    iget v6, v2, Lt9/a;->i:I

    .line 425
    .line 426
    invoke-virtual {v4, v6}, Lw7/p;->I(I)V

    .line 427
    .line 428
    .line 429
    invoke-virtual {v5, v4}, Lm9/f;->p(Lw7/p;)V

    .line 430
    .line 431
    .line 432
    invoke-virtual {v2, v5, v9, v0, v1}, Lt9/a;->b(Lm9/f;ZLandroid/graphics/Rect;[I)V

    .line 433
    .line 434
    .line 435
    invoke-virtual {v0}, Landroid/graphics/Rect;->width()I

    .line 436
    .line 437
    .line 438
    move-result v4

    .line 439
    invoke-virtual {v0}, Landroid/graphics/Rect;->height()I

    .line 440
    .line 441
    .line 442
    move-result v5

    .line 443
    sget-object v6, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 444
    .line 445
    invoke-static {v1, v4, v5, v6}, Landroid/graphics/Bitmap;->createBitmap([IIILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    .line 446
    .line 447
    .line 448
    move-result-object v11

    .line 449
    iget v1, v0, Landroid/graphics/Rect;->left:I

    .line 450
    .line 451
    int-to-float v1, v1

    .line 452
    iget v4, v2, Lt9/a;->e:I

    .line 453
    .line 454
    int-to-float v4, v4

    .line 455
    div-float v15, v1, v4

    .line 456
    .line 457
    iget v1, v0, Landroid/graphics/Rect;->top:I

    .line 458
    .line 459
    int-to-float v1, v1

    .line 460
    iget v4, v2, Lt9/a;->f:I

    .line 461
    .line 462
    int-to-float v4, v4

    .line 463
    div-float v12, v1, v4

    .line 464
    .line 465
    invoke-virtual {v0}, Landroid/graphics/Rect;->width()I

    .line 466
    .line 467
    .line 468
    move-result v1

    .line 469
    int-to-float v1, v1

    .line 470
    iget v4, v2, Lt9/a;->e:I

    .line 471
    .line 472
    int-to-float v4, v4

    .line 473
    div-float v19, v1, v4

    .line 474
    .line 475
    invoke-virtual {v0}, Landroid/graphics/Rect;->height()I

    .line 476
    .line 477
    .line 478
    move-result v0

    .line 479
    int-to-float v0, v0

    .line 480
    iget v1, v2, Lt9/a;->f:I

    .line 481
    .line 482
    int-to-float v1, v1

    .line 483
    div-float v20, v0, v1

    .line 484
    .line 485
    new-instance v7, Lv7/b;

    .line 486
    .line 487
    const/4 v8, 0x0

    .line 488
    const/4 v9, 0x0

    .line 489
    const/4 v13, 0x0

    .line 490
    const/4 v14, 0x0

    .line 491
    const/16 v16, 0x0

    .line 492
    .line 493
    const/high16 v17, -0x80000000

    .line 494
    .line 495
    const v18, -0x800001

    .line 496
    .line 497
    .line 498
    const/16 v21, 0x0

    .line 499
    .line 500
    const/high16 v22, -0x1000000

    .line 501
    .line 502
    const/16 v24, 0x0

    .line 503
    .line 504
    const/16 v25, 0x0

    .line 505
    .line 506
    move-object v10, v9

    .line 507
    move/from16 v23, v17

    .line 508
    .line 509
    invoke-direct/range {v7 .. v25}, Lv7/b;-><init>(Ljava/lang/CharSequence;Landroid/text/Layout$Alignment;Landroid/text/Layout$Alignment;Landroid/graphics/Bitmap;FIIFIIFFFZIIFI)V

    .line 510
    .line 511
    .line 512
    move-object v10, v7

    .line 513
    goto :goto_4

    .line 514
    :cond_a
    :goto_3
    const/4 v10, 0x0

    .line 515
    :goto_4
    new-instance v4, Ll9/a;

    .line 516
    .line 517
    if-eqz v10, :cond_b

    .line 518
    .line 519
    invoke-static {v10}, Lhr/h0;->u(Ljava/lang/Object;)Lhr/x0;

    .line 520
    .line 521
    .line 522
    move-result-object v0

    .line 523
    :goto_5
    move-object v9, v0

    .line 524
    goto :goto_6

    .line 525
    :cond_b
    sget-object v0, Lhr/h0;->e:Lhr/f0;

    .line 526
    .line 527
    sget-object v0, Lhr/x0;->h:Lhr/x0;

    .line 528
    .line 529
    goto :goto_5

    .line 530
    :goto_6
    const-wide v5, -0x7fffffffffffffffL    # -4.9E-324

    .line 531
    .line 532
    .line 533
    .line 534
    .line 535
    const-wide/32 v7, 0x4c4b40

    .line 536
    .line 537
    .line 538
    invoke-direct/range {v4 .. v9}, Ll9/a;-><init>(JJLjava/util/List;)V

    .line 539
    .line 540
    .line 541
    invoke-interface {v3, v4}, Lw7/f;->accept(Ljava/lang/Object;)V

    .line 542
    .line 543
    .line 544
    return-void

    .line 545
    :pswitch_5
    iget-object v4, v0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 546
    .line 547
    check-cast v4, Lo9/a;

    .line 548
    .line 549
    iget-object v5, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 550
    .line 551
    check-cast v5, Lw7/p;

    .line 552
    .line 553
    iget-object v10, v0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 554
    .line 555
    check-cast v10, Lw7/p;

    .line 556
    .line 557
    add-int v13, v2, p3

    .line 558
    .line 559
    invoke-virtual {v10, v13, v1}, Lw7/p;->G(I[B)V

    .line 560
    .line 561
    .line 562
    invoke-virtual {v10, v2}, Lw7/p;->I(I)V

    .line 563
    .line 564
    .line 565
    iget-object v1, v0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 566
    .line 567
    check-cast v1, Ljava/util/zip/Inflater;

    .line 568
    .line 569
    if-nez v1, :cond_c

    .line 570
    .line 571
    new-instance v1, Ljava/util/zip/Inflater;

    .line 572
    .line 573
    invoke-direct {v1}, Ljava/util/zip/Inflater;-><init>()V

    .line 574
    .line 575
    .line 576
    iput-object v1, v0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 577
    .line 578
    :cond_c
    iget-object v0, v0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 579
    .line 580
    check-cast v0, Ljava/util/zip/Inflater;

    .line 581
    .line 582
    sget-object v1, Lw7/w;->a:Ljava/lang/String;

    .line 583
    .line 584
    invoke-virtual {v10}, Lw7/p;->a()I

    .line 585
    .line 586
    .line 587
    move-result v1

    .line 588
    if-lez v1, :cond_d

    .line 589
    .line 590
    iget-object v1, v10, Lw7/p;->a:[B

    .line 591
    .line 592
    iget v2, v10, Lw7/p;->b:I

    .line 593
    .line 594
    aget-byte v1, v1, v2

    .line 595
    .line 596
    and-int/2addr v1, v8

    .line 597
    if-ne v1, v7, :cond_d

    .line 598
    .line 599
    invoke-static {v10, v5, v0}, Lw7/w;->y(Lw7/p;Lw7/p;Ljava/util/zip/Inflater;)Z

    .line 600
    .line 601
    .line 602
    move-result v0

    .line 603
    if-eqz v0, :cond_d

    .line 604
    .line 605
    iget-object v0, v5, Lw7/p;->a:[B

    .line 606
    .line 607
    iget v1, v5, Lw7/p;->c:I

    .line 608
    .line 609
    invoke-virtual {v10, v1, v0}, Lw7/p;->G(I[B)V

    .line 610
    .line 611
    .line 612
    :cond_d
    iput v9, v4, Lo9/a;->d:I

    .line 613
    .line 614
    iget-object v0, v4, Lo9/a;->b:[I

    .line 615
    .line 616
    iget-object v1, v4, Lo9/a;->a:Lw7/p;

    .line 617
    .line 618
    iput v9, v4, Lo9/a;->e:I

    .line 619
    .line 620
    iput v9, v4, Lo9/a;->f:I

    .line 621
    .line 622
    iput v9, v4, Lo9/a;->g:I

    .line 623
    .line 624
    iput v9, v4, Lo9/a;->h:I

    .line 625
    .line 626
    iput v9, v4, Lo9/a;->i:I

    .line 627
    .line 628
    invoke-virtual {v1, v9}, Lw7/p;->F(I)V

    .line 629
    .line 630
    .line 631
    iput-boolean v9, v4, Lo9/a;->c:Z

    .line 632
    .line 633
    new-instance v2, Ljava/util/ArrayList;

    .line 634
    .line 635
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 636
    .line 637
    .line 638
    :goto_7
    invoke-virtual {v10}, Lw7/p;->a()I

    .line 639
    .line 640
    .line 641
    move-result v5

    .line 642
    if-lt v5, v6, :cond_21

    .line 643
    .line 644
    iget v5, v10, Lw7/p;->c:I

    .line 645
    .line 646
    invoke-virtual {v10}, Lw7/p;->w()I

    .line 647
    .line 648
    .line 649
    move-result v7

    .line 650
    invoke-virtual {v10}, Lw7/p;->C()I

    .line 651
    .line 652
    .line 653
    move-result v13

    .line 654
    iget v14, v10, Lw7/p;->b:I

    .line 655
    .line 656
    add-int/2addr v14, v13

    .line 657
    if-le v14, v5, :cond_e

    .line 658
    .line 659
    invoke-virtual {v10, v5}, Lw7/p;->I(I)V

    .line 660
    .line 661
    .line 662
    move v11, v9

    .line 663
    move v5, v12

    .line 664
    const/4 v6, 0x0

    .line 665
    const/4 v15, 0x4

    .line 666
    move v9, v8

    .line 667
    goto/16 :goto_16

    .line 668
    .line 669
    :cond_e
    const/16 v5, 0x80

    .line 670
    .line 671
    if-eq v7, v5, :cond_18

    .line 672
    .line 673
    packed-switch v7, :pswitch_data_2

    .line 674
    .line 675
    .line 676
    :goto_8
    move v9, v8

    .line 677
    move v5, v12

    .line 678
    const/4 v15, 0x4

    .line 679
    goto/16 :goto_d

    .line 680
    .line 681
    :pswitch_6
    const/16 v5, 0x13

    .line 682
    .line 683
    if-ge v13, v5, :cond_f

    .line 684
    .line 685
    goto :goto_8

    .line 686
    :cond_f
    invoke-virtual {v10}, Lw7/p;->C()I

    .line 687
    .line 688
    .line 689
    move-result v5

    .line 690
    iput v5, v4, Lo9/a;->d:I

    .line 691
    .line 692
    invoke-virtual {v10}, Lw7/p;->C()I

    .line 693
    .line 694
    .line 695
    move-result v5

    .line 696
    iput v5, v4, Lo9/a;->e:I

    .line 697
    .line 698
    const/16 v5, 0xb

    .line 699
    .line 700
    invoke-virtual {v10, v5}, Lw7/p;->J(I)V

    .line 701
    .line 702
    .line 703
    invoke-virtual {v10}, Lw7/p;->C()I

    .line 704
    .line 705
    .line 706
    move-result v5

    .line 707
    iput v5, v4, Lo9/a;->f:I

    .line 708
    .line 709
    invoke-virtual {v10}, Lw7/p;->C()I

    .line 710
    .line 711
    .line 712
    move-result v5

    .line 713
    iput v5, v4, Lo9/a;->g:I

    .line 714
    .line 715
    goto :goto_8

    .line 716
    :pswitch_7
    const/4 v7, 0x4

    .line 717
    if-ge v13, v7, :cond_10

    .line 718
    .line 719
    move v15, v7

    .line 720
    goto :goto_b

    .line 721
    :cond_10
    invoke-virtual {v10, v6}, Lw7/p;->J(I)V

    .line 722
    .line 723
    .line 724
    invoke-virtual {v10}, Lw7/p;->w()I

    .line 725
    .line 726
    .line 727
    move-result v7

    .line 728
    and-int/2addr v5, v7

    .line 729
    if-eqz v5, :cond_11

    .line 730
    .line 731
    move v5, v12

    .line 732
    goto :goto_9

    .line 733
    :cond_11
    move v5, v9

    .line 734
    :goto_9
    add-int/lit8 v7, v13, -0x4

    .line 735
    .line 736
    if-eqz v5, :cond_14

    .line 737
    .line 738
    const/4 v5, 0x7

    .line 739
    if-ge v7, v5, :cond_12

    .line 740
    .line 741
    const/4 v15, 0x4

    .line 742
    goto :goto_b

    .line 743
    :cond_12
    invoke-virtual {v10}, Lw7/p;->z()I

    .line 744
    .line 745
    .line 746
    move-result v5

    .line 747
    const/4 v15, 0x4

    .line 748
    if-ge v5, v15, :cond_13

    .line 749
    .line 750
    goto :goto_b

    .line 751
    :cond_13
    invoke-virtual {v10}, Lw7/p;->C()I

    .line 752
    .line 753
    .line 754
    move-result v7

    .line 755
    iput v7, v4, Lo9/a;->h:I

    .line 756
    .line 757
    invoke-virtual {v10}, Lw7/p;->C()I

    .line 758
    .line 759
    .line 760
    move-result v7

    .line 761
    iput v7, v4, Lo9/a;->i:I

    .line 762
    .line 763
    add-int/lit8 v5, v5, -0x4

    .line 764
    .line 765
    invoke-virtual {v1, v5}, Lw7/p;->F(I)V

    .line 766
    .line 767
    .line 768
    add-int/lit8 v7, v13, -0xb

    .line 769
    .line 770
    goto :goto_a

    .line 771
    :cond_14
    const/4 v15, 0x4

    .line 772
    :goto_a
    iget v5, v1, Lw7/p;->b:I

    .line 773
    .line 774
    iget v13, v1, Lw7/p;->c:I

    .line 775
    .line 776
    if-ge v5, v13, :cond_15

    .line 777
    .line 778
    if-lez v7, :cond_15

    .line 779
    .line 780
    sub-int/2addr v13, v5

    .line 781
    invoke-static {v7, v13}, Ljava/lang/Math;->min(II)I

    .line 782
    .line 783
    .line 784
    move-result v7

    .line 785
    iget-object v13, v1, Lw7/p;->a:[B

    .line 786
    .line 787
    invoke-virtual {v10, v13, v5, v7}, Lw7/p;->h([BII)V

    .line 788
    .line 789
    .line 790
    add-int/2addr v5, v7

    .line 791
    invoke-virtual {v1, v5}, Lw7/p;->I(I)V

    .line 792
    .line 793
    .line 794
    :cond_15
    :goto_b
    move v9, v8

    .line 795
    move v5, v12

    .line 796
    goto/16 :goto_d

    .line 797
    .line 798
    :pswitch_8
    const/4 v15, 0x4

    .line 799
    rem-int/lit8 v7, v13, 0x5

    .line 800
    .line 801
    if-eq v7, v11, :cond_16

    .line 802
    .line 803
    goto :goto_b

    .line 804
    :cond_16
    invoke-virtual {v10, v11}, Lw7/p;->J(I)V

    .line 805
    .line 806
    .line 807
    invoke-static {v0, v9}, Ljava/util/Arrays;->fill([II)V

    .line 808
    .line 809
    .line 810
    div-int/lit8 v13, v13, 0x5

    .line 811
    .line 812
    move v7, v9

    .line 813
    :goto_c
    if-ge v7, v13, :cond_17

    .line 814
    .line 815
    invoke-virtual {v10}, Lw7/p;->w()I

    .line 816
    .line 817
    .line 818
    move-result v16

    .line 819
    move/from16 p0, v5

    .line 820
    .line 821
    invoke-virtual {v10}, Lw7/p;->w()I

    .line 822
    .line 823
    .line 824
    move-result v5

    .line 825
    invoke-virtual {v10}, Lw7/p;->w()I

    .line 826
    .line 827
    .line 828
    move-result v17

    .line 829
    invoke-virtual {v10}, Lw7/p;->w()I

    .line 830
    .line 831
    .line 832
    move-result v18

    .line 833
    invoke-virtual {v10}, Lw7/p;->w()I

    .line 834
    .line 835
    .line 836
    move-result v19

    .line 837
    move/from16 v21, v7

    .line 838
    .line 839
    int-to-double v6, v5

    .line 840
    add-int/lit8 v5, v17, -0x80

    .line 841
    .line 842
    int-to-double v11, v5

    .line 843
    const-wide v23, 0x3ff66e978d4fdf3bL    # 1.402

    .line 844
    .line 845
    .line 846
    .line 847
    .line 848
    mul-double v23, v23, v11

    .line 849
    .line 850
    add-double v8, v23, v6

    .line 851
    .line 852
    double-to-int v8, v8

    .line 853
    add-int/lit8 v9, v18, -0x80

    .line 854
    .line 855
    move-wide/from16 v23, v6

    .line 856
    .line 857
    int-to-double v5, v9

    .line 858
    const-wide v26, 0x3fd60663c74fb54aL    # 0.34414

    .line 859
    .line 860
    .line 861
    .line 862
    .line 863
    mul-double v26, v26, v5

    .line 864
    .line 865
    sub-double v26, v23, v26

    .line 866
    .line 867
    const-wide v28, 0x3fe6da3c21187e7cL    # 0.71414

    .line 868
    .line 869
    .line 870
    .line 871
    .line 872
    mul-double v11, v11, v28

    .line 873
    .line 874
    sub-double v11, v26, v11

    .line 875
    .line 876
    double-to-int v7, v11

    .line 877
    const-wide v11, 0x3ffc5a1cac083127L    # 1.772

    .line 878
    .line 879
    .line 880
    .line 881
    .line 882
    mul-double/2addr v5, v11

    .line 883
    add-double v5, v5, v23

    .line 884
    .line 885
    double-to-int v5, v5

    .line 886
    shl-int/lit8 v6, v19, 0x18

    .line 887
    .line 888
    const/16 v9, 0xff

    .line 889
    .line 890
    const/4 v11, 0x0

    .line 891
    invoke-static {v8, v11, v9}, Lw7/w;->g(III)I

    .line 892
    .line 893
    .line 894
    move-result v8

    .line 895
    shl-int/lit8 v8, v8, 0x10

    .line 896
    .line 897
    or-int/2addr v6, v8

    .line 898
    invoke-static {v7, v11, v9}, Lw7/w;->g(III)I

    .line 899
    .line 900
    .line 901
    move-result v7

    .line 902
    shl-int/lit8 v7, v7, 0x8

    .line 903
    .line 904
    or-int/2addr v6, v7

    .line 905
    invoke-static {v5, v11, v9}, Lw7/w;->g(III)I

    .line 906
    .line 907
    .line 908
    move-result v5

    .line 909
    or-int/2addr v5, v6

    .line 910
    aput v5, v0, v16

    .line 911
    .line 912
    add-int/lit8 v7, v21, 0x1

    .line 913
    .line 914
    move/from16 v5, p0

    .line 915
    .line 916
    move v8, v9

    .line 917
    const/4 v6, 0x3

    .line 918
    const/4 v9, 0x0

    .line 919
    const/4 v11, 0x2

    .line 920
    const/4 v12, 0x1

    .line 921
    goto :goto_c

    .line 922
    :cond_17
    move v9, v8

    .line 923
    move v5, v12

    .line 924
    iput-boolean v5, v4, Lo9/a;->c:Z

    .line 925
    .line 926
    :goto_d
    const/4 v11, 0x0

    .line 927
    const/16 v26, 0x0

    .line 928
    .line 929
    goto/16 :goto_15

    .line 930
    .line 931
    :cond_18
    move v9, v8

    .line 932
    move v5, v12

    .line 933
    const/4 v15, 0x4

    .line 934
    iget v6, v4, Lo9/a;->d:I

    .line 935
    .line 936
    if-eqz v6, :cond_1f

    .line 937
    .line 938
    iget v6, v4, Lo9/a;->e:I

    .line 939
    .line 940
    if-eqz v6, :cond_1f

    .line 941
    .line 942
    iget v6, v4, Lo9/a;->h:I

    .line 943
    .line 944
    if-eqz v6, :cond_1f

    .line 945
    .line 946
    iget v6, v4, Lo9/a;->i:I

    .line 947
    .line 948
    if-eqz v6, :cond_1f

    .line 949
    .line 950
    iget v6, v1, Lw7/p;->c:I

    .line 951
    .line 952
    if-eqz v6, :cond_1f

    .line 953
    .line 954
    iget v7, v1, Lw7/p;->b:I

    .line 955
    .line 956
    if-ne v7, v6, :cond_1f

    .line 957
    .line 958
    iget-boolean v6, v4, Lo9/a;->c:Z

    .line 959
    .line 960
    if-nez v6, :cond_19

    .line 961
    .line 962
    goto/16 :goto_13

    .line 963
    .line 964
    :cond_19
    const/4 v11, 0x0

    .line 965
    invoke-virtual {v1, v11}, Lw7/p;->I(I)V

    .line 966
    .line 967
    .line 968
    iget v6, v4, Lo9/a;->h:I

    .line 969
    .line 970
    iget v7, v4, Lo9/a;->i:I

    .line 971
    .line 972
    mul-int/2addr v6, v7

    .line 973
    new-array v7, v6, [I

    .line 974
    .line 975
    const/4 v11, 0x0

    .line 976
    :cond_1a
    :goto_e
    if-ge v11, v6, :cond_1e

    .line 977
    .line 978
    invoke-virtual {v1}, Lw7/p;->w()I

    .line 979
    .line 980
    .line 981
    move-result v8

    .line 982
    if-eqz v8, :cond_1b

    .line 983
    .line 984
    add-int/lit8 v12, v11, 0x1

    .line 985
    .line 986
    aget v8, v0, v8

    .line 987
    .line 988
    aput v8, v7, v11

    .line 989
    .line 990
    :goto_f
    move v11, v12

    .line 991
    goto :goto_e

    .line 992
    :cond_1b
    invoke-virtual {v1}, Lw7/p;->w()I

    .line 993
    .line 994
    .line 995
    move-result v8

    .line 996
    if-eqz v8, :cond_1a

    .line 997
    .line 998
    and-int/lit8 v12, v8, 0x40

    .line 999
    .line 1000
    if-nez v12, :cond_1c

    .line 1001
    .line 1002
    and-int/lit8 v12, v8, 0x3f

    .line 1003
    .line 1004
    goto :goto_10

    .line 1005
    :cond_1c
    and-int/lit8 v12, v8, 0x3f

    .line 1006
    .line 1007
    shl-int/lit8 v12, v12, 0x8

    .line 1008
    .line 1009
    invoke-virtual {v1}, Lw7/p;->w()I

    .line 1010
    .line 1011
    .line 1012
    move-result v13

    .line 1013
    or-int/2addr v12, v13

    .line 1014
    :goto_10
    and-int/lit16 v8, v8, 0x80

    .line 1015
    .line 1016
    if-nez v8, :cond_1d

    .line 1017
    .line 1018
    const/16 v25, 0x0

    .line 1019
    .line 1020
    aget v8, v0, v25

    .line 1021
    .line 1022
    goto :goto_11

    .line 1023
    :cond_1d
    invoke-virtual {v1}, Lw7/p;->w()I

    .line 1024
    .line 1025
    .line 1026
    move-result v8

    .line 1027
    aget v8, v0, v8

    .line 1028
    .line 1029
    :goto_11
    add-int/2addr v12, v11

    .line 1030
    invoke-static {v7, v11, v12, v8}, Ljava/util/Arrays;->fill([IIII)V

    .line 1031
    .line 1032
    .line 1033
    goto :goto_f

    .line 1034
    :cond_1e
    iget v6, v4, Lo9/a;->h:I

    .line 1035
    .line 1036
    iget v8, v4, Lo9/a;->i:I

    .line 1037
    .line 1038
    sget-object v11, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 1039
    .line 1040
    invoke-static {v7, v6, v8, v11}, Landroid/graphics/Bitmap;->createBitmap([IIILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    .line 1041
    .line 1042
    .line 1043
    move-result-object v30

    .line 1044
    iget v6, v4, Lo9/a;->f:I

    .line 1045
    .line 1046
    int-to-float v6, v6

    .line 1047
    iget v7, v4, Lo9/a;->d:I

    .line 1048
    .line 1049
    int-to-float v7, v7

    .line 1050
    div-float v34, v6, v7

    .line 1051
    .line 1052
    iget v6, v4, Lo9/a;->g:I

    .line 1053
    .line 1054
    int-to-float v6, v6

    .line 1055
    iget v8, v4, Lo9/a;->e:I

    .line 1056
    .line 1057
    int-to-float v8, v8

    .line 1058
    div-float v31, v6, v8

    .line 1059
    .line 1060
    iget v6, v4, Lo9/a;->h:I

    .line 1061
    .line 1062
    int-to-float v6, v6

    .line 1063
    div-float v38, v6, v7

    .line 1064
    .line 1065
    iget v6, v4, Lo9/a;->i:I

    .line 1066
    .line 1067
    int-to-float v6, v6

    .line 1068
    div-float v39, v6, v8

    .line 1069
    .line 1070
    new-instance v26, Lv7/b;

    .line 1071
    .line 1072
    const/16 v27, 0x0

    .line 1073
    .line 1074
    const/16 v28, 0x0

    .line 1075
    .line 1076
    const/16 v32, 0x0

    .line 1077
    .line 1078
    const/16 v33, 0x0

    .line 1079
    .line 1080
    const/16 v35, 0x0

    .line 1081
    .line 1082
    const/high16 v36, -0x80000000

    .line 1083
    .line 1084
    const v37, -0x800001

    .line 1085
    .line 1086
    .line 1087
    const/16 v40, 0x0

    .line 1088
    .line 1089
    const/high16 v41, -0x1000000

    .line 1090
    .line 1091
    const/16 v43, 0x0

    .line 1092
    .line 1093
    const/16 v44, 0x0

    .line 1094
    .line 1095
    move-object/from16 v29, v28

    .line 1096
    .line 1097
    move/from16 v42, v36

    .line 1098
    .line 1099
    invoke-direct/range {v26 .. v44}, Lv7/b;-><init>(Ljava/lang/CharSequence;Landroid/text/Layout$Alignment;Landroid/text/Layout$Alignment;Landroid/graphics/Bitmap;FIIFIIFFFZIIFI)V

    .line 1100
    .line 1101
    .line 1102
    :goto_12
    const/4 v11, 0x0

    .line 1103
    goto :goto_14

    .line 1104
    :cond_1f
    :goto_13
    const/16 v26, 0x0

    .line 1105
    .line 1106
    goto :goto_12

    .line 1107
    :goto_14
    iput v11, v4, Lo9/a;->d:I

    .line 1108
    .line 1109
    iput v11, v4, Lo9/a;->e:I

    .line 1110
    .line 1111
    iput v11, v4, Lo9/a;->f:I

    .line 1112
    .line 1113
    iput v11, v4, Lo9/a;->g:I

    .line 1114
    .line 1115
    iput v11, v4, Lo9/a;->h:I

    .line 1116
    .line 1117
    iput v11, v4, Lo9/a;->i:I

    .line 1118
    .line 1119
    invoke-virtual {v1, v11}, Lw7/p;->F(I)V

    .line 1120
    .line 1121
    .line 1122
    iput-boolean v11, v4, Lo9/a;->c:Z

    .line 1123
    .line 1124
    :goto_15
    invoke-virtual {v10, v14}, Lw7/p;->I(I)V

    .line 1125
    .line 1126
    .line 1127
    move-object/from16 v6, v26

    .line 1128
    .line 1129
    :goto_16
    if-eqz v6, :cond_20

    .line 1130
    .line 1131
    invoke-virtual {v2, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1132
    .line 1133
    .line 1134
    :cond_20
    move v12, v5

    .line 1135
    move v8, v9

    .line 1136
    move v9, v11

    .line 1137
    const/4 v6, 0x3

    .line 1138
    const/4 v11, 0x2

    .line 1139
    goto/16 :goto_7

    .line 1140
    .line 1141
    :cond_21
    new-instance v18, Ll9/a;

    .line 1142
    .line 1143
    const-wide v19, -0x7fffffffffffffffL    # -4.9E-324

    .line 1144
    .line 1145
    .line 1146
    .line 1147
    .line 1148
    const-wide v21, -0x7fffffffffffffffL    # -4.9E-324

    .line 1149
    .line 1150
    .line 1151
    .line 1152
    .line 1153
    move-object/from16 v23, v2

    .line 1154
    .line 1155
    invoke-direct/range {v18 .. v23}, Ll9/a;-><init>(JJLjava/util/List;)V

    .line 1156
    .line 1157
    .line 1158
    move-object/from16 v0, v18

    .line 1159
    .line 1160
    invoke-interface {v3, v0}, Lw7/f;->accept(Ljava/lang/Object;)V

    .line 1161
    .line 1162
    .line 1163
    return-void

    .line 1164
    nop

    .line 1165
    :pswitch_data_0
    .packed-switch 0x16
        :pswitch_5
    .end packed-switch

    .line 1166
    .line 1167
    .line 1168
    .line 1169
    .line 1170
    .line 1171
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch

    .line 1172
    .line 1173
    .line 1174
    .line 1175
    .line 1176
    .line 1177
    .line 1178
    .line 1179
    .line 1180
    .line 1181
    .line 1182
    .line 1183
    .line 1184
    .line 1185
    .line 1186
    .line 1187
    .line 1188
    .line 1189
    :pswitch_data_2
    .packed-switch 0x14
        :pswitch_8
        :pswitch_7
        :pswitch_6
    .end packed-switch
.end method

.method public get()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lj1/a;

    .line 4
    .line 5
    iget-object v0, v0, Lj1/a;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Lsr/f;

    .line 8
    .line 9
    iget-object v1, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v1, Lkx0/a;

    .line 12
    .line 13
    invoke-interface {v1}, Lkx0/a;->get()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    check-cast v1, Lku/j;

    .line 18
    .line 19
    iget-object v2, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v2, Lkx0/a;

    .line 22
    .line 23
    invoke-interface {v2}, Lkx0/a;->get()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    check-cast v2, Lpx0/g;

    .line 28
    .line 29
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast p0, Lju/c;

    .line 32
    .line 33
    invoke-interface {p0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    check-cast p0, Lhu/r0;

    .line 38
    .line 39
    new-instance v3, Lhu/n;

    .line 40
    .line 41
    invoke-direct {v3, v0, v1, v2, p0}, Lhu/n;-><init>(Lsr/f;Lku/j;Lpx0/g;Lhu/r0;)V

    .line 42
    .line 43
    .line 44
    return-object v3
.end method

.method public h(Lc1/p;Lc1/p;Lc1/p;)J
    .locals 8

    .line 1
    invoke-virtual {p1}, Lc1/p;->b()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const-wide/16 v1, 0x0

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    :goto_0
    if-ge v3, v0, :cond_0

    .line 9
    .line 10
    iget-object v4, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v4, Lc1/q;

    .line 13
    .line 14
    invoke-interface {v4, v3}, Lc1/q;->get(I)Lc1/b0;

    .line 15
    .line 16
    .line 17
    move-result-object v4

    .line 18
    invoke-virtual {p1, v3}, Lc1/p;->a(I)F

    .line 19
    .line 20
    .line 21
    move-result v5

    .line 22
    invoke-virtual {p2, v3}, Lc1/p;->a(I)F

    .line 23
    .line 24
    .line 25
    move-result v6

    .line 26
    invoke-virtual {p3, v3}, Lc1/p;->a(I)F

    .line 27
    .line 28
    .line 29
    move-result v7

    .line 30
    invoke-interface {v4, v5, v6, v7}, Lc1/b0;->e(FFF)J

    .line 31
    .line 32
    .line 33
    move-result-wide v4

    .line 34
    invoke-static {v1, v2, v4, v5}, Ljava/lang/Math;->max(JJ)J

    .line 35
    .line 36
    .line 37
    move-result-wide v1

    .line 38
    add-int/lit8 v3, v3, 0x1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    return-wide v1
.end method

.method public i(Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lm6/w;

    .line 4
    .line 5
    instance-of v1, p1, Lm6/h;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    move-object v1, p1

    .line 10
    check-cast v1, Lm6/h;

    .line 11
    .line 12
    iget v2, v1, Lm6/h;->g:I

    .line 13
    .line 14
    const/high16 v3, -0x80000000

    .line 15
    .line 16
    and-int v4, v2, v3

    .line 17
    .line 18
    if-eqz v4, :cond_0

    .line 19
    .line 20
    sub-int/2addr v2, v3

    .line 21
    iput v2, v1, Lm6/h;->g:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v1, Lm6/h;

    .line 25
    .line 26
    invoke-direct {v1, p0, p1}, Lm6/h;-><init>(Lcom/google/firebase/messaging/w;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object p1, v1, Lm6/h;->e:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v3, v1, Lm6/h;->g:I

    .line 34
    .line 35
    const/4 v4, 0x2

    .line 36
    const/4 v5, 0x1

    .line 37
    if-eqz v3, :cond_3

    .line 38
    .line 39
    if-eq v3, v5, :cond_2

    .line 40
    .line 41
    if-ne v3, v4, :cond_1

    .line 42
    .line 43
    iget-object p0, v1, Lm6/h;->d:Lcom/google/firebase/messaging/w;

    .line 44
    .line 45
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_2
    iget-object p0, v1, Lm6/h;->d:Lcom/google/firebase/messaging/w;

    .line 58
    .line 59
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    goto :goto_4

    .line 63
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    iget-object p1, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast p1, Ljava/util/List;

    .line 69
    .line 70
    if-eqz p1, :cond_6

    .line 71
    .line 72
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 73
    .line 74
    .line 75
    move-result p1

    .line 76
    if-eqz p1, :cond_4

    .line 77
    .line 78
    goto :goto_2

    .line 79
    :cond_4
    invoke-virtual {v0}, Lm6/w;->g()Lm6/i0;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    new-instance v3, Lm6/k;

    .line 84
    .line 85
    const/4 v5, 0x0

    .line 86
    invoke-direct {v3, v0, p0, v5}, Lm6/k;-><init>(Lm6/w;Lcom/google/firebase/messaging/w;Lkotlin/coroutines/Continuation;)V

    .line 87
    .line 88
    .line 89
    iput-object p0, v1, Lm6/h;->d:Lcom/google/firebase/messaging/w;

    .line 90
    .line 91
    iput v4, v1, Lm6/h;->g:I

    .line 92
    .line 93
    invoke-interface {p1, v3, v1}, Lm6/i0;->a(Lay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object p1

    .line 97
    if-ne p1, v2, :cond_5

    .line 98
    .line 99
    goto :goto_3

    .line 100
    :cond_5
    :goto_1
    check-cast p1, Lm6/d;

    .line 101
    .line 102
    goto :goto_5

    .line 103
    :cond_6
    :goto_2
    iput-object p0, v1, Lm6/h;->d:Lcom/google/firebase/messaging/w;

    .line 104
    .line 105
    iput v5, v1, Lm6/h;->g:I

    .line 106
    .line 107
    const/4 p1, 0x0

    .line 108
    invoke-static {v0, p1, v1}, Lm6/w;->f(Lm6/w;ZLrx0/c;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object p1

    .line 112
    if-ne p1, v2, :cond_7

    .line 113
    .line 114
    :goto_3
    return-object v2

    .line 115
    :cond_7
    :goto_4
    check-cast p1, Lm6/d;

    .line 116
    .line 117
    :goto_5
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 118
    .line 119
    check-cast p0, Lm6/w;

    .line 120
    .line 121
    iget-object p0, p0, Lm6/w;->h:Lm6/x;

    .line 122
    .line 123
    invoke-virtual {p0, p1}, Lm6/x;->b(Lm6/z0;)V

    .line 124
    .line 125
    .line 126
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 127
    .line 128
    return-object p0
.end method

.method public j(Lk/a;)Lk/e;
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const/4 v2, 0x0

    .line 10
    :goto_0
    if-ge v2, v1, :cond_1

    .line 11
    .line 12
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v3

    .line 16
    check-cast v3, Lk/e;

    .line 17
    .line 18
    if-eqz v3, :cond_0

    .line 19
    .line 20
    iget-object v4, v3, Lk/e;->b:Lk/a;

    .line 21
    .line 22
    if-ne v4, p1, :cond_0

    .line 23
    .line 24
    return-object v3

    .line 25
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_1
    new-instance v1, Lk/e;

    .line 29
    .line 30
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p0, Landroid/content/Context;

    .line 33
    .line 34
    invoke-direct {v1, p0, p1}, Lk/e;-><init>(Landroid/content/Context;Lk/a;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    return-object v1
.end method

.method public l(Lhy0/d;Ljava/lang/String;)Landroidx/lifecycle/b1;
    .locals 4

    .line 1
    const-string v0, "modelClass"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "key"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Lr7/c;

    .line 14
    .line 15
    monitor-enter v0

    .line 16
    :try_start_0
    iget-object v1, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v1, Landroidx/lifecycle/h1;

    .line 19
    .line 20
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    iget-object v1, v1, Landroidx/lifecycle/h1;->a:Ljava/util/LinkedHashMap;

    .line 24
    .line 25
    invoke-virtual {v1, p2}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    check-cast v1, Landroidx/lifecycle/b1;

    .line 30
    .line 31
    invoke-interface {p1, v1}, Lhy0/d;->isInstance(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v2

    .line 35
    if-eqz v2, :cond_1

    .line 36
    .line 37
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast p0, Landroidx/lifecycle/e1;

    .line 40
    .line 41
    instance-of p1, p0, Landroidx/lifecycle/y0;

    .line 42
    .line 43
    if-eqz p1, :cond_0

    .line 44
    .line 45
    check-cast p0, Landroidx/lifecycle/y0;

    .line 46
    .line 47
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 51
    .line 52
    .line 53
    iget-object p1, p0, Landroidx/lifecycle/y0;->d:Landroidx/lifecycle/r;

    .line 54
    .line 55
    if-eqz p1, :cond_0

    .line 56
    .line 57
    iget-object p0, p0, Landroidx/lifecycle/y0;->e:Lra/d;

    .line 58
    .line 59
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    invoke-static {v1, p0, p1}, Landroidx/lifecycle/v0;->a(Landroidx/lifecycle/b1;Lra/d;Landroidx/lifecycle/r;)V

    .line 63
    .line 64
    .line 65
    goto :goto_0

    .line 66
    :catchall_0
    move-exception p0

    .line 67
    goto :goto_4

    .line 68
    :cond_0
    :goto_0
    const-string p0, "null cannot be cast to non-null type T of androidx.lifecycle.viewmodel.ViewModelProviderImpl.getViewModel"

    .line 69
    .line 70
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    goto :goto_3

    .line 74
    :cond_1
    new-instance v1, Lp7/e;

    .line 75
    .line 76
    iget-object v2, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast v2, Lp7/c;

    .line 79
    .line 80
    invoke-direct {v1, v2}, Lp7/e;-><init>(Lp7/c;)V

    .line 81
    .line 82
    .line 83
    sget-object v2, Landroidx/lifecycle/g1;->b:Lwe0/b;

    .line 84
    .line 85
    iget-object v3, v1, Lp7/c;->a:Ljava/util/LinkedHashMap;

    .line 86
    .line 87
    invoke-interface {v3, v2, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    iget-object v2, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 91
    .line 92
    check-cast v2, Landroidx/lifecycle/e1;

    .line 93
    .line 94
    const-string v3, "factory"

    .line 95
    .line 96
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 97
    .line 98
    .line 99
    :try_start_1
    invoke-interface {v2, p1, v1}, Landroidx/lifecycle/e1;->a(Lhy0/d;Lp7/e;)Landroidx/lifecycle/b1;

    .line 100
    .line 101
    .line 102
    move-result-object p1
    :try_end_1
    .catch Ljava/lang/AbstractMethodError; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 103
    :goto_1
    move-object v1, p1

    .line 104
    goto :goto_2

    .line 105
    :catch_0
    :try_start_2
    invoke-static {p1}, Ljp/p1;->c(Lhy0/d;)Ljava/lang/Class;

    .line 106
    .line 107
    .line 108
    move-result-object v3

    .line 109
    invoke-interface {v2, v3, v1}, Landroidx/lifecycle/e1;->c(Ljava/lang/Class;Lp7/e;)Landroidx/lifecycle/b1;

    .line 110
    .line 111
    .line 112
    move-result-object p1
    :try_end_2
    .catch Ljava/lang/AbstractMethodError; {:try_start_2 .. :try_end_2} :catch_1
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 113
    goto :goto_1

    .line 114
    :catch_1
    :try_start_3
    invoke-static {p1}, Ljp/p1;->c(Lhy0/d;)Ljava/lang/Class;

    .line 115
    .line 116
    .line 117
    move-result-object p1

    .line 118
    invoke-interface {v2, p1}, Landroidx/lifecycle/e1;->b(Ljava/lang/Class;)Landroidx/lifecycle/b1;

    .line 119
    .line 120
    .line 121
    move-result-object p1

    .line 122
    goto :goto_1

    .line 123
    :goto_2
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast p0, Landroidx/lifecycle/h1;

    .line 126
    .line 127
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 128
    .line 129
    .line 130
    const-string p1, "viewModel"

    .line 131
    .line 132
    invoke-static {v1, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    iget-object p0, p0, Landroidx/lifecycle/h1;->a:Ljava/util/LinkedHashMap;

    .line 136
    .line 137
    invoke-interface {p0, p2, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object p0

    .line 141
    check-cast p0, Landroidx/lifecycle/b1;

    .line 142
    .line 143
    if-eqz p0, :cond_2

    .line 144
    .line 145
    invoke-virtual {p0}, Landroidx/lifecycle/b1;->clear$lifecycle_viewmodel_release()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 146
    .line 147
    .line 148
    :cond_2
    :goto_3
    monitor-exit v0

    .line 149
    return-object v1

    .line 150
    :goto_4
    monitor-exit v0

    .line 151
    throw p0
.end method

.method public m(Landroid/content/Context;)Z
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/Boolean;

    .line 4
    .line 5
    if-nez v0, :cond_1

    .line 6
    .line 7
    const-string v0, "android.permission.ACCESS_NETWORK_STATE"

    .line 8
    .line 9
    invoke-virtual {p1, v0}, Landroid/content/Context;->checkCallingOrSelfPermission(Ljava/lang/String;)I

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    if-nez p1, :cond_0

    .line 14
    .line 15
    const/4 p1, 0x1

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 p1, 0x0

    .line 18
    :goto_0
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 23
    .line 24
    :cond_1
    iget-object p1, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast p1, Ljava/lang/Boolean;

    .line 27
    .line 28
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    if-nez p1, :cond_2

    .line 33
    .line 34
    const/4 p1, 0x3

    .line 35
    const-string v0, "FirebaseMessaging"

    .line 36
    .line 37
    invoke-static {v0, p1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    if-eqz p1, :cond_2

    .line 42
    .line 43
    const-string p1, "Missing Permission: android.permission.ACCESS_NETWORK_STATE this should normally be included by the manifest merger, but may needed to be manually added to your manifest"

    .line 44
    .line 45
    invoke-static {v0, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 46
    .line 47
    .line 48
    :cond_2
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast p0, Ljava/lang/Boolean;

    .line 51
    .line 52
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    return p0
.end method

.method public n(Landroid/content/Context;)Z
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/Boolean;

    .line 4
    .line 5
    if-nez v0, :cond_1

    .line 6
    .line 7
    const-string v0, "android.permission.WAKE_LOCK"

    .line 8
    .line 9
    invoke-virtual {p1, v0}, Landroid/content/Context;->checkCallingOrSelfPermission(Ljava/lang/String;)I

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    if-nez p1, :cond_0

    .line 14
    .line 15
    const/4 p1, 0x1

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 p1, 0x0

    .line 18
    :goto_0
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 23
    .line 24
    :cond_1
    iget-object p1, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast p1, Ljava/lang/Boolean;

    .line 27
    .line 28
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    if-nez p1, :cond_2

    .line 33
    .line 34
    const/4 p1, 0x3

    .line 35
    const-string v0, "FirebaseMessaging"

    .line 36
    .line 37
    invoke-static {v0, p1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    if-eqz p1, :cond_2

    .line 42
    .line 43
    const-string p1, "Missing Permission: android.permission.WAKE_LOCK this should normally be included by the manifest merger, but may needed to be manually added to your manifest"

    .line 44
    .line 45
    invoke-static {v0, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 46
    .line 47
    .line 48
    :cond_2
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast p0, Ljava/lang/Boolean;

    .line 51
    .line 52
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    return p0
.end method

.method public o(Lk/a;Landroid/view/MenuItem;)Z
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/view/ActionMode$Callback;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lcom/google/firebase/messaging/w;->j(Lk/a;)Lk/e;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    new-instance v1, Ll/s;

    .line 10
    .line 11
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Landroid/content/Context;

    .line 14
    .line 15
    check-cast p2, Lv5/a;

    .line 16
    .line 17
    invoke-direct {v1, p0, p2}, Ll/s;-><init>(Landroid/content/Context;Lv5/a;)V

    .line 18
    .line 19
    .line 20
    invoke-interface {v0, p1, v1}, Landroid/view/ActionMode$Callback;->onActionItemClicked(Landroid/view/ActionMode;Landroid/view/MenuItem;)Z

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    return p0
.end method

.method public p(Lk/a;Landroid/view/Menu;)Z
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/view/ActionMode$Callback;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lcom/google/firebase/messaging/w;->j(Lk/a;)Lk/e;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    iget-object v1, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v1, Landroidx/collection/a1;

    .line 12
    .line 13
    invoke-virtual {v1, p2}, Landroidx/collection/a1;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    check-cast v2, Landroid/view/Menu;

    .line 18
    .line 19
    if-nez v2, :cond_0

    .line 20
    .line 21
    new-instance v2, Ll/a0;

    .line 22
    .line 23
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast p0, Landroid/content/Context;

    .line 26
    .line 27
    move-object v3, p2

    .line 28
    check-cast v3, Ll/l;

    .line 29
    .line 30
    invoke-direct {v2, p0, v3}, Ll/a0;-><init>(Landroid/content/Context;Ll/l;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v1, p2, v2}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    :cond_0
    invoke-interface {v0, p1, v2}, Landroid/view/ActionMode$Callback;->onCreateActionMode(Landroid/view/ActionMode;Landroid/view/Menu;)Z

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    return p0
.end method

.method public q(Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p1, Lm6/t0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lm6/t0;

    .line 7
    .line 8
    iget v1, v0, Lm6/t0;->h:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lm6/t0;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lm6/t0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lm6/t0;-><init>(Lcom/google/firebase/messaging/w;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lm6/t0;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lm6/t0;->h:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    const/4 v6, 0x0

    .line 36
    if-eqz v2, :cond_3

    .line 37
    .line 38
    if-eq v2, v4, :cond_2

    .line 39
    .line 40
    if-ne v2, v3, :cond_1

    .line 41
    .line 42
    iget-object p0, v0, Lm6/t0;->e:Lez0/a;

    .line 43
    .line 44
    iget-object v0, v0, Lm6/t0;->d:Lcom/google/firebase/messaging/w;

    .line 45
    .line 46
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 47
    .line 48
    .line 49
    goto :goto_3

    .line 50
    :catchall_0
    move-exception p1

    .line 51
    goto :goto_4

    .line 52
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 53
    .line 54
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 55
    .line 56
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p0

    .line 60
    :cond_2
    iget-object p0, v0, Lm6/t0;->e:Lez0/a;

    .line 61
    .line 62
    iget-object v2, v0, Lm6/t0;->d:Lcom/google/firebase/messaging/w;

    .line 63
    .line 64
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    move-object p1, p0

    .line 68
    move-object p0, v2

    .line 69
    goto :goto_1

    .line 70
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    iget-object p1, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast p1, Lvy0/r;

    .line 76
    .line 77
    invoke-virtual {p1}, Lvy0/p1;->U()Z

    .line 78
    .line 79
    .line 80
    move-result p1

    .line 81
    if-eqz p1, :cond_4

    .line 82
    .line 83
    return-object v5

    .line 84
    :cond_4
    iget-object p1, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 85
    .line 86
    check-cast p1, Lez0/c;

    .line 87
    .line 88
    iput-object p0, v0, Lm6/t0;->d:Lcom/google/firebase/messaging/w;

    .line 89
    .line 90
    iput-object p1, v0, Lm6/t0;->e:Lez0/a;

    .line 91
    .line 92
    iput v4, v0, Lm6/t0;->h:I

    .line 93
    .line 94
    invoke-virtual {p1, v0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v2

    .line 98
    if-ne v2, v1, :cond_5

    .line 99
    .line 100
    goto :goto_2

    .line 101
    :cond_5
    :goto_1
    :try_start_1
    iget-object v2, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 102
    .line 103
    check-cast v2, Lvy0/r;

    .line 104
    .line 105
    invoke-virtual {v2}, Lvy0/p1;->U()Z

    .line 106
    .line 107
    .line 108
    move-result v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 109
    if-eqz v2, :cond_6

    .line 110
    .line 111
    invoke-interface {p1, v6}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    return-object v5

    .line 115
    :cond_6
    :try_start_2
    iput-object p0, v0, Lm6/t0;->d:Lcom/google/firebase/messaging/w;

    .line 116
    .line 117
    iput-object p1, v0, Lm6/t0;->e:Lez0/a;

    .line 118
    .line 119
    iput v3, v0, Lm6/t0;->h:I

    .line 120
    .line 121
    invoke-virtual {p0, v0}, Lcom/google/firebase/messaging/w;->i(Lrx0/c;)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 125
    if-ne v0, v1, :cond_7

    .line 126
    .line 127
    :goto_2
    return-object v1

    .line 128
    :cond_7
    move-object v0, p0

    .line 129
    move-object p0, p1

    .line 130
    :goto_3
    :try_start_3
    iget-object p1, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 131
    .line 132
    check-cast p1, Lvy0/r;

    .line 133
    .line 134
    invoke-virtual {p1, v5}, Lvy0/p1;->W(Ljava/lang/Object;)Z
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 135
    .line 136
    .line 137
    invoke-interface {p0, v6}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 138
    .line 139
    .line 140
    return-object v5

    .line 141
    :catchall_1
    move-exception p0

    .line 142
    move-object v7, p1

    .line 143
    move-object p1, p0

    .line 144
    move-object p0, v7

    .line 145
    :goto_4
    invoke-interface {p0, v6}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 146
    .line 147
    .line 148
    throw p1
.end method

.method public r(Landroid/graphics/drawable/Drawable;)V
    .locals 3

    .line 1
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/view/ViewGroup;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Landroid/view/View;->setBackgroundDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 6
    .line 7
    .line 8
    new-instance v0, Landroid/graphics/Rect;

    .line 9
    .line 10
    invoke-direct {v0}, Landroid/graphics/Rect;-><init>()V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p1, v0}, Landroid/graphics/drawable/Drawable;->getPadding(Landroid/graphics/Rect;)Z

    .line 14
    .line 15
    .line 16
    iget p1, v0, Landroid/graphics/Rect;->left:I

    .line 17
    .line 18
    iget v1, v0, Landroid/graphics/Rect;->top:I

    .line 19
    .line 20
    iget v2, v0, Landroid/graphics/Rect;->right:I

    .line 21
    .line 22
    iget v0, v0, Landroid/graphics/Rect;->bottom:I

    .line 23
    .line 24
    invoke-virtual {p0, p1, v1, v2, v0}, Landroid/view/View;->setPadding(IIII)V

    .line 25
    .line 26
    .line 27
    return-void
.end method

.method public s(Lp3/k;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lp3/y;

    .line 4
    .line 5
    sget-object v1, Lp3/y;->e:Lp3/y;

    .line 6
    .line 7
    if-ne v0, v1, :cond_1

    .line 8
    .line 9
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v0, Lt3/y;

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    const-wide/16 v1, 0x0

    .line 16
    .line 17
    invoke-interface {v0, v1, v2}, Lt3/y;->R(J)J

    .line 18
    .line 19
    .line 20
    move-result-wide v0

    .line 21
    new-instance v2, Lp3/z;

    .line 22
    .line 23
    iget-object v3, p0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v3, Lp3/a0;

    .line 26
    .line 27
    const/4 v4, 0x1

    .line 28
    invoke-direct {v2, v3, v4}, Lp3/z;-><init>(Lp3/a0;I)V

    .line 29
    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    invoke-static {p1, v0, v1, v2, v3}, Lp3/s;->i(Lp3/k;JLay0/k;Z)V

    .line 33
    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 37
    .line 38
    const-string p1, "layoutCoordinates not set"

    .line 39
    .line 40
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw p0

    .line 44
    :cond_1
    :goto_0
    sget-object p1, Lp3/y;->f:Lp3/y;

    .line 45
    .line 46
    iput-object p1, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 47
    .line 48
    return-void
.end method

.method public t(JLc1/p;Lc1/p;Lc1/p;)Lc1/p;
    .locals 14

    .line 1
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lc1/p;

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    invoke-virtual/range {p3 .. p3}, Lc1/p;->c()Lc1/p;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iput-object v0, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 12
    .line 13
    :cond_0
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v0, Lc1/p;

    .line 16
    .line 17
    const/4 v1, 0x0

    .line 18
    const-string v2, "valueVector"

    .line 19
    .line 20
    if-eqz v0, :cond_4

    .line 21
    .line 22
    invoke-virtual {v0}, Lc1/p;->b()I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    const/4 v3, 0x0

    .line 27
    :goto_0
    if-ge v3, v0, :cond_2

    .line 28
    .line 29
    iget-object v4, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v4, Lc1/p;

    .line 32
    .line 33
    if-eqz v4, :cond_1

    .line 34
    .line 35
    iget-object v5, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v5, Lc1/q;

    .line 38
    .line 39
    invoke-interface {v5, v3}, Lc1/q;->get(I)Lc1/b0;

    .line 40
    .line 41
    .line 42
    move-result-object v6

    .line 43
    move-object/from16 v5, p3

    .line 44
    .line 45
    invoke-virtual {v5, v3}, Lc1/p;->a(I)F

    .line 46
    .line 47
    .line 48
    move-result v9

    .line 49
    move-object/from16 v12, p4

    .line 50
    .line 51
    invoke-virtual {v12, v3}, Lc1/p;->a(I)F

    .line 52
    .line 53
    .line 54
    move-result v10

    .line 55
    move-object/from16 v13, p5

    .line 56
    .line 57
    invoke-virtual {v13, v3}, Lc1/p;->a(I)F

    .line 58
    .line 59
    .line 60
    move-result v11

    .line 61
    move-wide v7, p1

    .line 62
    invoke-interface/range {v6 .. v11}, Lc1/b0;->c(JFFF)F

    .line 63
    .line 64
    .line 65
    move-result v6

    .line 66
    invoke-virtual {v4, v3, v6}, Lc1/p;->e(IF)V

    .line 67
    .line 68
    .line 69
    add-int/lit8 v3, v3, 0x1

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_1
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    throw v1

    .line 76
    :cond_2
    iget-object p0, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast p0, Lc1/p;

    .line 79
    .line 80
    if-eqz p0, :cond_3

    .line 81
    .line 82
    return-object p0

    .line 83
    :cond_3
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    throw v1

    .line 87
    :cond_4
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    throw v1
.end method

.method public v(Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lcom/google/android/gms/internal/measurement/u;

    .line 4
    .line 5
    invoke-virtual {v0, p0, p1}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public varargs w(Lcom/google/firebase/messaging/w;[Lcom/google/android/gms/internal/measurement/w3;)Lcom/google/android/gms/internal/measurement/o;
    .locals 4

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/o;->m0:Lcom/google/android/gms/internal/measurement/s;

    .line 2
    .line 3
    array-length v1, p2

    .line 4
    const/4 v2, 0x0

    .line 5
    :goto_0
    if-ge v2, v1, :cond_2

    .line 6
    .line 7
    aget-object v0, p2, v2

    .line 8
    .line 9
    invoke-static {v0}, Ljp/xd;->c(Lcom/google/android/gms/internal/measurement/w3;)Lcom/google/android/gms/internal/measurement/o;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iget-object v3, p0, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v3, Lcom/google/firebase/messaging/w;

    .line 16
    .line 17
    invoke-static {v3}, Ljp/wd;->l(Lcom/google/firebase/messaging/w;)V

    .line 18
    .line 19
    .line 20
    instance-of v3, v0, Lcom/google/android/gms/internal/measurement/p;

    .line 21
    .line 22
    if-nez v3, :cond_0

    .line 23
    .line 24
    instance-of v3, v0, Lcom/google/android/gms/internal/measurement/n;

    .line 25
    .line 26
    if-eqz v3, :cond_1

    .line 27
    .line 28
    :cond_0
    iget-object v3, p0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v3, Lcom/google/android/gms/internal/measurement/u;

    .line 31
    .line 32
    invoke-virtual {v3, p1, v0}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    :cond_1
    add-int/lit8 v2, v2, 0x1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_2
    return-object v0
.end method

.method public x(Lcom/google/android/gms/internal/measurement/e;)Lcom/google/android/gms/internal/measurement/o;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/o;->m0:Lcom/google/android/gms/internal/measurement/s;

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/e;->s()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    :cond_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    if-eqz v2, :cond_1

    .line 12
    .line 13
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    check-cast v0, Ljava/lang/Integer;

    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    iget-object v2, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v2, Lcom/google/android/gms/internal/measurement/u;

    .line 26
    .line 27
    invoke-virtual {p1, v0}, Lcom/google/android/gms/internal/measurement/e;->u(I)Lcom/google/android/gms/internal/measurement/o;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    invoke-virtual {v2, p0, v0}, Lcom/google/android/gms/internal/measurement/u;->c(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/o;)Lcom/google/android/gms/internal/measurement/o;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    instance-of v2, v0, Lcom/google/android/gms/internal/measurement/g;

    .line 36
    .line 37
    if-eqz v2, :cond_0

    .line 38
    .line 39
    :cond_1
    return-object v0
.end method

.method public z()Lcom/google/firebase/messaging/w;
    .locals 2

    .line 1
    new-instance v0, Lcom/google/firebase/messaging/w;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Lcom/google/android/gms/internal/measurement/u;

    .line 6
    .line 7
    invoke-direct {v0, p0, v1}, Lcom/google/firebase/messaging/w;-><init>(Lcom/google/firebase/messaging/w;Lcom/google/android/gms/internal/measurement/u;)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method
