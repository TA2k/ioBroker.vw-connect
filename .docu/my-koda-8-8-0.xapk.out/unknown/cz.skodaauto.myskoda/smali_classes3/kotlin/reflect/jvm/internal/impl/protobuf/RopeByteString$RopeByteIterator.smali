.class Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$RopeByteIterator;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString$ByteIterator;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "RopeByteIterator"
.end annotation


# instance fields
.field private bytes:Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString$ByteIterator;

.field bytesRemaining:I

.field private final pieces:Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$PieceIterator;

.field final synthetic this$0:Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString;


# direct methods
.method private constructor <init>(Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString;)V
    .locals 2

    .line 2
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$RopeByteIterator;->this$0:Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$PieceIterator;

    const/4 v1, 0x0

    invoke-direct {v0, p1, v1}, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$PieceIterator;-><init>(Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$1;)V

    iput-object v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$RopeByteIterator;->pieces:Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$PieceIterator;

    .line 4
    invoke-virtual {v0}, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$PieceIterator;->next()Lkotlin/reflect/jvm/internal/impl/protobuf/LiteralByteString;

    move-result-object v0

    invoke-virtual {v0}, Lkotlin/reflect/jvm/internal/impl/protobuf/LiteralByteString;->iterator()Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString$ByteIterator;

    move-result-object v0

    iput-object v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$RopeByteIterator;->bytes:Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString$ByteIterator;

    .line 5
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString;->size()I

    move-result p1

    iput p1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$RopeByteIterator;->bytesRemaining:I

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString;Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$1;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$RopeByteIterator;-><init>(Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString;)V

    return-void
.end method


# virtual methods
.method public hasNext()Z
    .locals 0

    .line 1
    iget p0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$RopeByteIterator;->bytesRemaining:I

    .line 2
    .line 3
    if-lez p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public next()Ljava/lang/Byte;
    .locals 0

    .line 2
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$RopeByteIterator;->nextByte()B

    move-result p0

    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic next()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$RopeByteIterator;->next()Ljava/lang/Byte;

    move-result-object p0

    return-object p0
.end method

.method public nextByte()B
    .locals 1

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$RopeByteIterator;->bytes:Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString$ByteIterator;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$RopeByteIterator;->pieces:Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$PieceIterator;

    .line 10
    .line 11
    invoke-virtual {v0}, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$PieceIterator;->next()Lkotlin/reflect/jvm/internal/impl/protobuf/LiteralByteString;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-virtual {v0}, Lkotlin/reflect/jvm/internal/impl/protobuf/LiteralByteString;->iterator()Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString$ByteIterator;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    iput-object v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$RopeByteIterator;->bytes:Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString$ByteIterator;

    .line 20
    .line 21
    :cond_0
    iget v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$RopeByteIterator;->bytesRemaining:I

    .line 22
    .line 23
    add-int/lit8 v0, v0, -0x1

    .line 24
    .line 25
    iput v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$RopeByteIterator;->bytesRemaining:I

    .line 26
    .line 27
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$RopeByteIterator;->bytes:Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString$ByteIterator;

    .line 28
    .line 29
    invoke-interface {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString$ByteIterator;->nextByte()B

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    return p0
.end method

.method public remove()V
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 4
    .line 5
    .line 6
    throw p0
.end method
