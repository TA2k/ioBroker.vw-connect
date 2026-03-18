.class public final Lor/b;
.super Lmr/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic b:I


# direct methods
.method public synthetic constructor <init>()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lor/b;->b:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Lor/c;)V
    .locals 0

    const/4 p1, 0x1

    iput p1, p0, Lor/b;->b:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final a(Lcom/google/crypto/tink/shaded/protobuf/a;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget p0, p0, Lor/b;->b:I

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    packed-switch p0, :pswitch_data_0

    .line 5
    .line 6
    .line 7
    check-cast p1, Lqr/l;

    .line 8
    .line 9
    invoke-static {}, Lqr/j;->s()Lqr/i;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/v;->c()V

    .line 14
    .line 15
    .line 16
    iget-object v1, p0, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 17
    .line 18
    check-cast v1, Lqr/j;

    .line 19
    .line 20
    invoke-static {v1}, Lqr/j;->m(Lqr/j;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p1}, Lqr/l;->p()Lqr/n;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/v;->c()V

    .line 28
    .line 29
    .line 30
    iget-object v2, p0, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 31
    .line 32
    check-cast v2, Lqr/j;

    .line 33
    .line 34
    invoke-static {v2, v1}, Lqr/j;->n(Lqr/j;Lqr/n;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {p1}, Lqr/l;->o()I

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    sget-object v1, Lrr/e;->a:Ley0/b;

    .line 42
    .line 43
    new-array v1, p1, [B

    .line 44
    .line 45
    sget-object v2, Lrr/e;->a:Ley0/b;

    .line 46
    .line 47
    invoke-virtual {v2}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v2

    .line 51
    check-cast v2, Ljava/security/SecureRandom;

    .line 52
    .line 53
    invoke-virtual {v2, v1}, Ljava/security/SecureRandom;->nextBytes([B)V

    .line 54
    .line 55
    .line 56
    invoke-static {v1, v0, p1}, Lcom/google/crypto/tink/shaded/protobuf/i;->g([BII)Lcom/google/crypto/tink/shaded/protobuf/h;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/v;->c()V

    .line 61
    .line 62
    .line 63
    iget-object v0, p0, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 64
    .line 65
    check-cast v0, Lqr/j;

    .line 66
    .line 67
    invoke-static {v0, p1}, Lqr/j;->o(Lqr/j;Lcom/google/crypto/tink/shaded/protobuf/h;)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/v;->a()Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    check-cast p0, Lqr/j;

    .line 75
    .line 76
    return-object p0

    .line 77
    :pswitch_0
    check-cast p1, Lqr/d;

    .line 78
    .line 79
    invoke-static {}, Lqr/b;->s()Lqr/a;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/v;->c()V

    .line 84
    .line 85
    .line 86
    iget-object v1, p0, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 87
    .line 88
    check-cast v1, Lqr/b;

    .line 89
    .line 90
    invoke-static {v1}, Lqr/b;->m(Lqr/b;)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {p1}, Lqr/d;->m()I

    .line 94
    .line 95
    .line 96
    move-result v1

    .line 97
    sget-object v2, Lrr/e;->a:Ley0/b;

    .line 98
    .line 99
    new-array v2, v1, [B

    .line 100
    .line 101
    sget-object v3, Lrr/e;->a:Ley0/b;

    .line 102
    .line 103
    invoke-virtual {v3}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v3

    .line 107
    check-cast v3, Ljava/security/SecureRandom;

    .line 108
    .line 109
    invoke-virtual {v3, v2}, Ljava/security/SecureRandom;->nextBytes([B)V

    .line 110
    .line 111
    .line 112
    invoke-static {v2, v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/i;->g([BII)Lcom/google/crypto/tink/shaded/protobuf/h;

    .line 113
    .line 114
    .line 115
    move-result-object v0

    .line 116
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/v;->c()V

    .line 117
    .line 118
    .line 119
    iget-object v1, p0, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 120
    .line 121
    check-cast v1, Lqr/b;

    .line 122
    .line 123
    invoke-static {v1, v0}, Lqr/b;->n(Lqr/b;Lcom/google/crypto/tink/shaded/protobuf/h;)V

    .line 124
    .line 125
    .line 126
    invoke-virtual {p1}, Lqr/d;->n()Lqr/e;

    .line 127
    .line 128
    .line 129
    move-result-object p1

    .line 130
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/v;->c()V

    .line 131
    .line 132
    .line 133
    iget-object v0, p0, Lcom/google/crypto/tink/shaded/protobuf/v;->e:Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 134
    .line 135
    check-cast v0, Lqr/b;

    .line 136
    .line 137
    invoke-static {v0, p1}, Lqr/b;->o(Lqr/b;Lqr/e;)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/v;->a()Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    check-cast p0, Lqr/b;

    .line 145
    .line 146
    return-object p0

    .line 147
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final b(Lcom/google/crypto/tink/shaded/protobuf/i;)Lcom/google/crypto/tink/shaded/protobuf/a;
    .locals 0

    .line 1
    iget p0, p0, Lor/b;->b:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/p;->a()Lcom/google/crypto/tink/shaded/protobuf/p;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-static {p1, p0}, Lqr/l;->r(Lcom/google/crypto/tink/shaded/protobuf/i;Lcom/google/crypto/tink/shaded/protobuf/p;)Lqr/l;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :pswitch_0
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/p;->a()Lcom/google/crypto/tink/shaded/protobuf/p;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-static {p1, p0}, Lqr/d;->o(Lcom/google/crypto/tink/shaded/protobuf/i;Lcom/google/crypto/tink/shaded/protobuf/p;)Lqr/d;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final c(Lcom/google/crypto/tink/shaded/protobuf/a;)V
    .locals 1

    .line 1
    iget p0, p0, Lor/b;->b:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lqr/l;

    .line 7
    .line 8
    invoke-virtual {p1}, Lqr/l;->o()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    const/16 v0, 0x10

    .line 13
    .line 14
    if-lt p0, v0, :cond_0

    .line 15
    .line 16
    invoke-virtual {p1}, Lqr/l;->p()Lqr/n;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-static {p0}, Lor/c;->L(Lqr/n;)V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :cond_0
    new-instance p0, Ljava/security/GeneralSecurityException;

    .line 25
    .line 26
    const-string p1, "key too short"

    .line 27
    .line 28
    invoke-direct {p0, p1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0

    .line 32
    :pswitch_0
    check-cast p1, Lqr/d;

    .line 33
    .line 34
    invoke-virtual {p1}, Lqr/d;->n()Lqr/e;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    invoke-static {p0}, Lor/c;->K(Lqr/e;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p1}, Lqr/d;->m()I

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    const/16 p1, 0x20

    .line 46
    .line 47
    if-ne p0, p1, :cond_1

    .line 48
    .line 49
    return-void

    .line 50
    :cond_1
    new-instance p0, Ljava/security/GeneralSecurityException;

    .line 51
    .line 52
    const-string p1, "AesCmacKey size wrong, must be 32 bytes"

    .line 53
    .line 54
    invoke-direct {p0, p1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    nop

    .line 59
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
