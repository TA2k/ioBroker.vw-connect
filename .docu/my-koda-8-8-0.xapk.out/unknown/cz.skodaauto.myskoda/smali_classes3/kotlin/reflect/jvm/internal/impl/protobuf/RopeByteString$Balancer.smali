.class Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$Balancer;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "Balancer"
.end annotation


# instance fields
.field private final prefixesStack:Ljava/util/Stack;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Stack<",
            "Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method private constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    new-instance v0, Ljava/util/Stack;

    invoke-direct {v0}, Ljava/util/Stack;-><init>()V

    iput-object v0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$Balancer;->prefixesStack:Ljava/util/Stack;

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$1;)V
    .locals 0

    .line 3
    invoke-direct {p0}, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$Balancer;-><init>()V

    return-void
.end method

.method public static synthetic access$100(Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$Balancer;Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;)Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$Balancer;->balance(Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;)Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private balance(Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;)Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;
    .locals 2

    .line 1
    invoke-direct {p0, p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$Balancer;->doBalance(Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;)V

    .line 2
    .line 3
    .line 4
    invoke-direct {p0, p2}, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$Balancer;->doBalance(Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;)V

    .line 5
    .line 6
    .line 7
    iget-object p1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$Balancer;->prefixesStack:Ljava/util/Stack;

    .line 8
    .line 9
    invoke-virtual {p1}, Ljava/util/Stack;->pop()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    check-cast p1, Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;

    .line 14
    .line 15
    :goto_0
    iget-object p2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$Balancer;->prefixesStack:Ljava/util/Stack;

    .line 16
    .line 17
    invoke-virtual {p2}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 18
    .line 19
    .line 20
    move-result p2

    .line 21
    if-nez p2, :cond_0

    .line 22
    .line 23
    iget-object p2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$Balancer;->prefixesStack:Ljava/util/Stack;

    .line 24
    .line 25
    invoke-virtual {p2}, Ljava/util/Stack;->pop()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p2

    .line 29
    check-cast p2, Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;

    .line 30
    .line 31
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString;

    .line 32
    .line 33
    const/4 v1, 0x0

    .line 34
    invoke-direct {v0, p2, p1, v1}, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString;-><init>(Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$1;)V

    .line 35
    .line 36
    .line 37
    move-object p1, v0

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    return-object p1
.end method

.method private doBalance(Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;)V
    .locals 2

    .line 1
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;->isBalanced()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-direct {p0, p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$Balancer;->insert(Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;)V

    .line 8
    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    instance-of v0, p1, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString;

    .line 12
    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    check-cast p1, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString;

    .line 16
    .line 17
    invoke-static {p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString;->access$400(Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString;)Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-direct {p0, v0}, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$Balancer;->doBalance(Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;)V

    .line 22
    .line 23
    .line 24
    invoke-static {p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString;->access$500(Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString;)Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    invoke-direct {p0, p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$Balancer;->doBalance(Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;)V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 33
    .line 34
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    new-instance v0, Ljava/lang/StringBuilder;

    .line 43
    .line 44
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    add-int/lit8 v1, v1, 0x31

    .line 49
    .line 50
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 51
    .line 52
    .line 53
    const-string v1, "Has a new type of ByteString been created? Found "

    .line 54
    .line 55
    invoke-static {v0, v1, p1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    throw p0
.end method

.method private getDepthBinForLength(I)I
    .locals 0

    .line 1
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString;->access$600()[I

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0, p1}, Ljava/util/Arrays;->binarySearch([II)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-gez p0, :cond_0

    .line 10
    .line 11
    add-int/lit8 p0, p0, 0x1

    .line 12
    .line 13
    neg-int p0, p0

    .line 14
    add-int/lit8 p0, p0, -0x1

    .line 15
    .line 16
    :cond_0
    return p0
.end method

.method private insert(Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;)V
    .locals 5

    .line 1
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-direct {p0, v0}, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$Balancer;->getDepthBinForLength(I)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString;->access$600()[I

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    add-int/lit8 v2, v0, 0x1

    .line 14
    .line 15
    aget v1, v1, v2

    .line 16
    .line 17
    iget-object v2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$Balancer;->prefixesStack:Ljava/util/Stack;

    .line 18
    .line 19
    invoke-virtual {v2}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-nez v2, :cond_3

    .line 24
    .line 25
    iget-object v2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$Balancer;->prefixesStack:Ljava/util/Stack;

    .line 26
    .line 27
    invoke-virtual {v2}, Ljava/util/Stack;->peek()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    check-cast v2, Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;

    .line 32
    .line 33
    invoke-virtual {v2}, Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;->size()I

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    if-lt v2, v1, :cond_0

    .line 38
    .line 39
    goto/16 :goto_2

    .line 40
    .line 41
    :cond_0
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString;->access$600()[I

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    aget v0, v1, v0

    .line 46
    .line 47
    iget-object v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$Balancer;->prefixesStack:Ljava/util/Stack;

    .line 48
    .line 49
    invoke-virtual {v1}, Ljava/util/Stack;->pop()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    check-cast v1, Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;

    .line 54
    .line 55
    :goto_0
    iget-object v2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$Balancer;->prefixesStack:Ljava/util/Stack;

    .line 56
    .line 57
    invoke-virtual {v2}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 58
    .line 59
    .line 60
    move-result v2

    .line 61
    const/4 v3, 0x0

    .line 62
    if-nez v2, :cond_1

    .line 63
    .line 64
    iget-object v2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$Balancer;->prefixesStack:Ljava/util/Stack;

    .line 65
    .line 66
    invoke-virtual {v2}, Ljava/util/Stack;->peek()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    check-cast v2, Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;

    .line 71
    .line 72
    invoke-virtual {v2}, Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;->size()I

    .line 73
    .line 74
    .line 75
    move-result v2

    .line 76
    if-ge v2, v0, :cond_1

    .line 77
    .line 78
    iget-object v2, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$Balancer;->prefixesStack:Ljava/util/Stack;

    .line 79
    .line 80
    invoke-virtual {v2}, Ljava/util/Stack;->pop()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v2

    .line 84
    check-cast v2, Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;

    .line 85
    .line 86
    new-instance v4, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString;

    .line 87
    .line 88
    invoke-direct {v4, v2, v1, v3}, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString;-><init>(Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$1;)V

    .line 89
    .line 90
    .line 91
    move-object v1, v4

    .line 92
    goto :goto_0

    .line 93
    :cond_1
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString;

    .line 94
    .line 95
    invoke-direct {v0, v1, p1, v3}, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString;-><init>(Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$1;)V

    .line 96
    .line 97
    .line 98
    :goto_1
    iget-object p1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$Balancer;->prefixesStack:Ljava/util/Stack;

    .line 99
    .line 100
    invoke-virtual {p1}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 101
    .line 102
    .line 103
    move-result p1

    .line 104
    if-nez p1, :cond_2

    .line 105
    .line 106
    invoke-virtual {v0}, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString;->size()I

    .line 107
    .line 108
    .line 109
    move-result p1

    .line 110
    invoke-direct {p0, p1}, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$Balancer;->getDepthBinForLength(I)I

    .line 111
    .line 112
    .line 113
    move-result p1

    .line 114
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString;->access$600()[I

    .line 115
    .line 116
    .line 117
    move-result-object v1

    .line 118
    add-int/lit8 p1, p1, 0x1

    .line 119
    .line 120
    aget p1, v1, p1

    .line 121
    .line 122
    iget-object v1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$Balancer;->prefixesStack:Ljava/util/Stack;

    .line 123
    .line 124
    invoke-virtual {v1}, Ljava/util/Stack;->peek()Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v1

    .line 128
    check-cast v1, Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;

    .line 129
    .line 130
    invoke-virtual {v1}, Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;->size()I

    .line 131
    .line 132
    .line 133
    move-result v1

    .line 134
    if-ge v1, p1, :cond_2

    .line 135
    .line 136
    iget-object p1, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$Balancer;->prefixesStack:Ljava/util/Stack;

    .line 137
    .line 138
    invoke-virtual {p1}, Ljava/util/Stack;->pop()Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object p1

    .line 142
    check-cast p1, Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;

    .line 143
    .line 144
    new-instance v1, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString;

    .line 145
    .line 146
    invoke-direct {v1, p1, v0, v3}, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString;-><init>(Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;Lkotlin/reflect/jvm/internal/impl/protobuf/ByteString;Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$1;)V

    .line 147
    .line 148
    .line 149
    move-object v0, v1

    .line 150
    goto :goto_1

    .line 151
    :cond_2
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$Balancer;->prefixesStack:Ljava/util/Stack;

    .line 152
    .line 153
    invoke-virtual {p0, v0}, Ljava/util/Stack;->push(Ljava/lang/Object;)Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    return-void

    .line 157
    :cond_3
    :goto_2
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/protobuf/RopeByteString$Balancer;->prefixesStack:Ljava/util/Stack;

    .line 158
    .line 159
    invoke-virtual {p0, p1}, Ljava/util/Stack;->push(Ljava/lang/Object;)Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    return-void
.end method
