.class public Lcom/google/android/filament/Texture$PixelBufferDescriptor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/Texture;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "PixelBufferDescriptor"
.end annotation


# instance fields
.field public alignment:I

.field public callback:Ljava/lang/Runnable;

.field public compressedFormat:Lcom/google/android/filament/Texture$CompressedFormat;

.field public compressedSizeInBytes:I

.field public format:Lcom/google/android/filament/Texture$Format;

.field public handler:Ljava/lang/Object;

.field public left:I

.field public storage:Ljava/nio/Buffer;

.field public stride:I

.field public top:I

.field public type:Lcom/google/android/filament/Texture$Type;


# direct methods
.method public constructor <init>(Ljava/nio/Buffer;Lcom/google/android/filament/Texture$Format;Lcom/google/android/filament/Texture$Type;)V
    .locals 10

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v4, 0x1

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    .line 11
    invoke-direct/range {v0 .. v9}, Lcom/google/android/filament/Texture$PixelBufferDescriptor;-><init>(Ljava/nio/Buffer;Lcom/google/android/filament/Texture$Format;Lcom/google/android/filament/Texture$Type;IIIILjava/lang/Object;Ljava/lang/Runnable;)V

    return-void
.end method

.method public constructor <init>(Ljava/nio/Buffer;Lcom/google/android/filament/Texture$Format;Lcom/google/android/filament/Texture$Type;I)V
    .locals 10

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move v4, p4

    .line 12
    invoke-direct/range {v0 .. v9}, Lcom/google/android/filament/Texture$PixelBufferDescriptor;-><init>(Ljava/nio/Buffer;Lcom/google/android/filament/Texture$Format;Lcom/google/android/filament/Texture$Type;IIIILjava/lang/Object;Ljava/lang/Runnable;)V

    return-void
.end method

.method public constructor <init>(Ljava/nio/Buffer;Lcom/google/android/filament/Texture$Format;Lcom/google/android/filament/Texture$Type;III)V
    .locals 10

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v7, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move v4, p4

    move v5, p5

    move/from16 v6, p6

    .line 13
    invoke-direct/range {v0 .. v9}, Lcom/google/android/filament/Texture$PixelBufferDescriptor;-><init>(Ljava/nio/Buffer;Lcom/google/android/filament/Texture$Format;Lcom/google/android/filament/Texture$Type;IIIILjava/lang/Object;Ljava/lang/Runnable;)V

    return-void
.end method

.method public constructor <init>(Ljava/nio/Buffer;Lcom/google/android/filament/Texture$Format;Lcom/google/android/filament/Texture$Type;IIIILjava/lang/Object;Ljava/lang/Runnable;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->storage:Ljava/nio/Buffer;

    .line 3
    iput p5, p0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->left:I

    .line 4
    iput p6, p0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->top:I

    .line 5
    iput-object p3, p0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->type:Lcom/google/android/filament/Texture$Type;

    .line 6
    iput p4, p0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->alignment:I

    .line 7
    iput p7, p0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->stride:I

    .line 8
    iput-object p2, p0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->format:Lcom/google/android/filament/Texture$Format;

    .line 9
    iput-object p8, p0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->handler:Ljava/lang/Object;

    .line 10
    iput-object p9, p0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->callback:Ljava/lang/Runnable;

    return-void
.end method

.method public constructor <init>(Ljava/nio/ByteBuffer;Lcom/google/android/filament/Texture$CompressedFormat;I)V
    .locals 2

    .line 14
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x1

    .line 15
    iput v0, p0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->alignment:I

    const/4 v1, 0x0

    .line 16
    iput v1, p0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->left:I

    .line 17
    iput v1, p0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->top:I

    .line 18
    iput v1, p0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->stride:I

    .line 19
    iput-object p1, p0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->storage:Ljava/nio/Buffer;

    .line 20
    sget-object p1, Lcom/google/android/filament/Texture$Type;->COMPRESSED:Lcom/google/android/filament/Texture$Type;

    iput-object p1, p0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->type:Lcom/google/android/filament/Texture$Type;

    .line 21
    iput v0, p0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->alignment:I

    .line 22
    iput-object p2, p0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->compressedFormat:Lcom/google/android/filament/Texture$CompressedFormat;

    .line 23
    iput p3, p0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->compressedSizeInBytes:I

    return-void
.end method

.method public static computeDataSize(Lcom/google/android/filament/Texture$Format;Lcom/google/android/filament/Texture$Type;III)I
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/Texture$Type;->COMPRESSED:Lcom/google/android/filament/Texture$Type;

    .line 2
    .line 3
    if-ne p1, v0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return p0

    .line 7
    :cond_0
    sget-object v0, Lcom/google/android/filament/Texture$1;->$SwitchMap$com$google$android$filament$Texture$Format:[I

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    aget p0, v0, p0

    .line 14
    .line 15
    const/4 v0, 0x2

    .line 16
    const/4 v1, 0x4

    .line 17
    packed-switch p0, :pswitch_data_0

    .line 18
    .line 19
    .line 20
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 21
    .line 22
    const-string p1, "unsupported format enum"

    .line 23
    .line 24
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    throw p0

    .line 28
    :pswitch_0
    move p0, v1

    .line 29
    goto :goto_0

    .line 30
    :pswitch_1
    const/4 p0, 0x3

    .line 31
    goto :goto_0

    .line 32
    :pswitch_2
    move p0, v0

    .line 33
    goto :goto_0

    .line 34
    :pswitch_3
    const/4 p0, 0x1

    .line 35
    :goto_0
    sget-object v2, Lcom/google/android/filament/Texture$1;->$SwitchMap$com$google$android$filament$Texture$Type:[I

    .line 36
    .line 37
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    aget p1, v2, p1

    .line 42
    .line 43
    packed-switch p1, :pswitch_data_1

    .line 44
    .line 45
    .line 46
    move v0, p0

    .line 47
    goto :goto_1

    .line 48
    :pswitch_4
    move v0, v1

    .line 49
    goto :goto_1

    .line 50
    :pswitch_5
    mul-int/lit8 v0, p0, 0x4

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :pswitch_6
    mul-int/lit8 v0, p0, 0x2

    .line 54
    .line 55
    :goto_1
    :pswitch_7
    mul-int/2addr v0, p2

    .line 56
    add-int/lit8 p0, p4, -0x1

    .line 57
    .line 58
    add-int/2addr p0, v0

    .line 59
    neg-int p1, p4

    .line 60
    and-int/2addr p0, p1

    .line 61
    mul-int/2addr p0, p3

    .line 62
    return p0

    .line 63
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_3
        :pswitch_3
        :pswitch_3
        :pswitch_3
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_1
        :pswitch_1
        :pswitch_0
        :pswitch_0
    .end packed-switch

    .line 64
    .line 65
    .line 66
    .line 67
    .line 68
    .line 69
    .line 70
    .line 71
    .line 72
    .line 73
    .line 74
    .line 75
    .line 76
    .line 77
    .line 78
    .line 79
    .line 80
    .line 81
    .line 82
    .line 83
    .line 84
    .line 85
    .line 86
    .line 87
    .line 88
    .line 89
    .line 90
    .line 91
    :pswitch_data_1
    .packed-switch 0x4
        :pswitch_6
        :pswitch_6
        :pswitch_6
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_4
        :pswitch_7
    .end packed-switch
.end method


# virtual methods
.method public setCallback(Ljava/lang/Object;Ljava/lang/Runnable;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->handler:Ljava/lang/Object;

    .line 2
    .line 3
    iput-object p2, p0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->callback:Ljava/lang/Runnable;

    .line 4
    .line 5
    return-void
.end method
